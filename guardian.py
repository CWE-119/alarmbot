"""
guardian.py - everything that watches and protects your servers:

  * full logging with audit-log attribution (who gave which role, who moved whom, bans, permissions ...)
  * message archive + attachment / avatar mirroring into Discord log channels (nothing hits the disk)
  * join / leave / invite tracking, profile + nickname history, alt-account heuristics
  * scoped message delete  (!alarmbot -d -u ... -t ... -c ...)
  * cross-server compromised-account protection

Loaded from main.py's setup_hook. All state lives in SQLite (see database.py), so it survives restarts.
"""
import asyncio
import collections
import hashlib
import io
import json
import os
import re
import time
import weakref
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import discord
import pytz
from dateutil.relativedelta import relativedelta
from discord.ext import commands, tasks

import database as db
import guardian_store as store

UTC = pytz.UTC
MAX_READ_BYTES = 25 * 1024 * 1024
MEDIA_WORKERS = 2
MEDIA_QUEUE_SIZE = 32
MAX_TIMEOUT = timedelta(days=27, hours=23)          # Discord caps a timeout at 28 days

CATEGORIES = {
    "messages":   "deleted / edited / bulk-deleted messages (+ who deleted)",
    "media":      "mirrored attachments and avatar snapshots",
    "members":    "joins, leaves, name / nickname / avatar changes",
    "voice":      "voice join / leave / move (+ who moved or disconnected whom), streams",
    "roles":      "roles given / removed (by whom), role + channel permission changes",
    "moderation": "bans, kicks, timeouts, server mute/deafen, prunes, automod",
    "server":     "channels, threads, invites, emoji, webhooks, server settings",
    "security":   "compromised-account flags and auto-deletions",
}

SAFE_DOMAINS = {
    "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "youtube.com", "youtu.be",
    "tenor.com", "giphy.com", "imgur.com", "twitter.com", "x.com", "github.com", "google.com",
    "wikipedia.org", "reddit.com", "twitch.tv", "spotify.com",
}
URL_RE = re.compile(r"https?://([^/\s<>]+)", re.I)
UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "mo": 2592000, "y": 31536000}
SPAN_PART = re.compile(r"(\d+)\s*(mo|y|w|d|h|m|s)", re.I)
SPAN_FULL = re.compile(r"(?:\d+\s*(?:mo|y|w|d|h|m|s)\s*)+", re.I)
FLAG_RE = re.compile(r"(?<!\S)-([dutc])(?![A-Za-z])", re.I)
ID_RE = re.compile(r"<[@#][!&]?(\d+)>|(\d{15,25})")

# audit actions that are merged into richer logs elsewhere (voice / message delete) -> not posted raw
AUDIT_MERGED = {"member_move", "member_disconnect", "message_delete", "message_bulk_delete"}
ICONS = {
    "kick": "👢", "ban": "🔨", "unban": "♻️", "member_prune": "🧹", "member_update": "🛠️",
    "member_role_update": "🎭", "role_create": "🆕", "role_update": "🎭", "role_delete": "🗑️",
    "channel_create": "🆕", "channel_update": "📝", "channel_delete": "🗑️",
    "overwrite_create": "🔐", "overwrite_update": "🔐", "overwrite_delete": "🔓",
    "invite_create": "✉️", "invite_delete": "✉️", "webhook_create": "🪝", "webhook_delete": "🪝",
    "emoji_create": "😀", "emoji_delete": "😀", "guild_update": "⚙️", "bot_add": "🤖",
}


# ---------------------------------------------------------------- helpers
def now_utc() -> datetime:
    return datetime.now(UTC)


def norm_text(s) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def text_hash(s):
    n = norm_text(s)
    return hashlib.sha256(n.encode()).hexdigest() if len(n) >= 15 else None


def domains_of(s) -> set:
    out = set()
    for d in URL_RE.findall(s or ""):
        d = d.lower().split("@")[-1].split(":")[0]
        if d.startswith("www."):
            d = d[4:]
        if d and not any(d == x or d.endswith("." + x) for x in SAFE_DOMAINS):
            out.add(d)
    return out


def urls_of(content: str) -> set:
    """Compare complete evidence URLs; a shared hostname is never enough."""
    urls = set()
    for value in re.findall(r"https?://[^\s<>]+", content or "", re.I):
        value = value.rstrip(".,!?)]}")
        try:
            parts = urlsplit(value)
            if parts.hostname:
                urls.add(urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                                    parts.path or "/", parts.query, "")))
        except ValueError:
            continue
    return urls


def can_moderate(actor, target, guild) -> bool:
    """The bot's role never substitutes for the invoking moderator's authority."""
    if target is None or target.id == actor.id or target.id == guild.owner_id:
        return False
    return actor.id == guild.owner_id or actor.top_role > target.top_role


def same_timeout(current, recorded: str) -> bool:
    return current is not None and abs((current - datetime.fromisoformat(recorded)).total_seconds()) < 1


def safe_name(n: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", n or "file")[:80]


def short(s, n=900) -> str:
    s = (s or "").replace("```", "'''")
    return s if len(s) <= n else s[: n - 1] + "…"


def ordinal(n: int) -> str:
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def human_age(since: datetime, now: datetime) -> str:
    """'3 years, 10 months and 2 days ago' (both datetimes timezone-aware)."""
    rd = relativedelta(now, since)
    parts = [f"{v} {unit}{'s' if v != 1 else ''}" for v, unit in
             ((rd.years, "year"), (rd.months, "month"), (rd.days, "day")) if v]
    if not parts:
        return "today"
    return (parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]) + " ago"


def parse_span(text):
    """'1H' '2d' '1w' '6mo' '1y' '1d12h' -> timedelta; 'all' -> 'all'; invalid -> None."""
    t = (text or "").strip().lower()
    if t in ("all", "forever", "*"):
        return "all"
    if not t or not SPAN_FULL.fullmatch(t):
        return None
    secs = sum(int(n) * UNIT[u] for n, u in SPAN_PART.findall(t))
    return timedelta(seconds=min(secs, 60 * 365 * 86400)) if secs > 0 else None


def parse_flags(raw: str) -> dict:
    parts = FLAG_RE.split(raw or "")
    return {parts[i].lower(): parts[i + 1].strip() for i in range(1, len(parts) - 1, 2)}


def target_id_of(entry) -> Optional[int]:
    t = entry.target
    return getattr(t, "id", None) or getattr(entry, "_target_id", None)


def pnames(p) -> set:
    return {n for n, v in p if v} if p is not None else set()


def fmt_ref(x, fallback_id=None) -> str:
    if x is None:
        return f"`{fallback_id}`" if fallback_id else "-"
    if isinstance(x, discord.Object):
        return f"`{x.id}`" + (f" ({x.name})" if hasattr(x, "name") else "")
    mention = getattr(x, "mention", None)
    if mention:
        return f"{mention} (`{x.id}`)"
    if isinstance(x, discord.Invite):
        return f"`{x.code}`"
    return str(x)[:100]


def fmt_val(v) -> str:
    if v is None:
        return "none"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, datetime):
        return f"<t:{int(v.timestamp())}:f>"
    if type(v).__module__.startswith("discord.enums") or (
            hasattr(v, "name") and hasattr(v, "value") and not isinstance(v, (str, list, set))):
        return f"`{v.name}`"
    if isinstance(v, (list, tuple, set)):
        return ", ".join(fmt_val(i) for i in list(v)[:8]) or "none"
    if getattr(v, "mention", None):
        return v.mention
    if hasattr(v, "name") and not isinstance(v, str):
        return f"`{v.name}`"
    return f"`{str(v)[:100]}`"


def perm_lines(label: str, before, after) -> Optional[str]:
    b, a = pnames(before), pnames(after)
    add, rem = sorted(a - b), sorted(b - a)
    if not add and not rem:
        return None
    parts = [f"➕ {', '.join(x.replace('_', ' ') for x in add)}" if add else "",
             f"➖ {', '.join(x.replace('_', ' ') for x in rem)}" if rem else ""]
    return "\n".join(p for p in parts if p)


class Confirm(discord.ui.View):
    def __init__(self, author_id: int):
        super().__init__(timeout=30)
        self.author_id = author_id
        self.value = False

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return interaction.user.id == self.author_id

    @discord.ui.button(label="Delete", style=discord.ButtonStyle.danger)
    async def yes(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.value = True
        await interaction.response.defer()
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def no(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        self.stop()


# ---------------------------------------------------------------- cog
class Guardian(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.flagged: dict = {}
        self.exempt: set = set()
        self.protect_off: set = set()
        self.network_enabled: set = set()
        self.trusted_sources: set = set()
        self.report_only: set = set()
        self.pattern_exempt: set = set()
        self.mirror_off: set = set()
        self.routes: dict = {}
        self.fp_cache: list = []
        self.purging: set = set()
        self.silent_ids: set = set()
        self.audit_buf = collections.deque(maxlen=300)
        self.invites: dict = {}          # guild_id -> {code: Invite}
        self.sem = asyncio.Semaphore(4)
        self._tasks: set = set()
        self._seeded = False
        self.media_queue = asyncio.Queue(maxsize=MEDIA_QUEUE_SIZE)
        self.media_workers = []
        self.media_dropped = 0
        self._notice_times = {}
        self._timeout_locks = weakref.WeakValueDictionary()

    # ------------------------------------------------------------ lifecycle
    async def cog_load(self):
        await store.init()
        await self.refresh_cache()
        self.enforce_loop.start()
        self.media_workers = [asyncio.create_task(self.media_worker()) for _ in range(MEDIA_WORKERS)]

    async def cog_unload(self):
        self.enforce_loop.cancel()
        for task in self.media_workers + list(self._tasks):
            task.cancel()
        await asyncio.gather(*self.media_workers, *list(self._tasks), return_exceptions=True)

    async def refresh_cache(self):
        snapshot = await store.snapshot()
        self.flagged = {(f["source_guild_id"], f["user_id"]): f for f in snapshot["flags"]}
        self.exempt = {(e["guild_id"], e["source_guild_id"], e["user_id"]) for e in snapshot["exempts"]}
        self.network_enabled = {s["guild_id"] for s in snapshot["settings"] if s["network_enabled"]}
        self.report_only = {s["guild_id"] for s in snapshot["settings"] if s["report_only"]}
        self.trusted_sources = {(s["guild_id"], s["source_guild_id"]) for s in snapshot["trust"]}
        self.pattern_exempt = {(s["guild_id"], s["pattern_id"]) for s in snapshot["pattern_exempts"]}
        self.mirror_off = await db.get_mirror_off()
        self.routes = await db.get_routes()
        self.fp_cache = []
        for f in snapshot["patterns"]:
            self.fp_cache.append({
                "id": f["id"], "source_guild_id": f["source_guild_id"],
                "user_id": f["user_id"], "hash": f["content_hash"], "norm": f["sample"] or "",
                "urls": set(json.loads(f["urls"])),
                "shas": set(json.loads(f["attachment_shas"])),
            })

    @commands.Cog.listener()
    async def on_ready(self):
        for g in self.bot.guilds:
            await self.cache_invites(g)
        if self._seeded:
            return
        self._seeded = True
        profiles, members, seen = [], [], set()
        for g in self.bot.guilds:
            for m in g.members:
                if m.id not in seen:
                    seen.add(m.id)
                    profiles.append(self.profile_dict(m))
                members.append({"guild_id": g.id, "user_id": m.id, "nickname": m.nick,
                                "joined": m.joined_at.isoformat() if m.joined_at else None})
        try:
            changed = await db.sync_profiles(profiles, members,
                                            complete_guild_ids=[g.id for g in self.bot.guilds if g.chunked])
            print(f"[guardian] synced {len(profiles)} profiles, {changed} offline changes recorded")
        except Exception as e:
            print(f"[guardian] startup sync failed: {e}")

    # ------------------------------------------------------------ small utils
    @staticmethod
    def profile_dict(u) -> dict:
        return {"user_id": u.id, "username": u.name, "global_name": getattr(u, "global_name", None),
                "avatar_hash": u.avatar.key if u.avatar else None,
                "created": u.created_at.isoformat(), "is_bot": int(u.bot)}

    async def log_channel(self, guild_id: int, category: str):
        rid = self.routes.get((guild_id, category))
        if rid == 0:
            return None
        if rid:
            channel = self.bot.get_channel(rid)
        else:
            settings = await db.get_log_settings(guild_id)
            channel = self.bot.get_channel(settings[0]) if settings and settings[0] else None
        return channel if channel and getattr(getattr(channel, "guild", None), "id", None) == guild_id else None

    async def send_log(self, guild_id: int, category: str, **kw):
        subject_id = kw.pop("_subject_id", None)
        ch = await self.log_channel(guild_id, category)
        if ch:
            try:
                kw.setdefault("allowed_mentions", discord.AllowedMentions.none())
                sent = await ch.send(**kw)
                if subject_id is not None:
                    await store.add_media(guild_id, subject_id, None, ch.id, sent.id, "member_log")
                return sent
            except discord.HTTPException:
                pass
        return None

    def spawn(self, coro):
        t = asyncio.create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def is_owner(self, user) -> bool:
        return await self.bot.is_owner(user)

    def consume(self, action: str, *, guild_id: int, target=None, channel=None, max_age=15):
        """Find (and use up one count of) a recent audit entry. Used to attribute moves/disconnects."""
        now = time.monotonic()
        for e in reversed(self.audit_buf):
            if e["guild_id"] != guild_id or e["action"] != action or now - e["ts"] > max_age or e["left"] <= 0:
                continue
            if target is not None and e["target"] != target:
                continue
            if channel is not None and e["channel"] != channel:
                continue
            e["left"] -= 1
            return e
        return None

    def find_recent(self, action: str, *, guild_id: int, target=None, channel=None, key=None, max_age=15):
        now = time.monotonic()
        for e in reversed(self.audit_buf):
            if e["guild_id"] != guild_id or e["action"] != action or now - e["ts"] > max_age:
                continue
            if target is not None and e["target"] != target:
                continue
            if channel is not None and e["channel"] != channel:
                continue
            if key is not None and key not in e["keys"]:
                continue
            return e
        return None

    async def mirror_avatar(self, user, guild_id: int) -> Optional[str]:
        """Snapshot an avatar once: bytes go memory -> log channel. Returns a Discord URL (never a file path)."""
        asset = user.avatar
        if asset is None:
            return None
        if not await db.should_archive(guild_id, 0, user.id):
            return None
        existing = await store.list_media(guild_id=guild_id, author_id=user.id, kind="avatar", asset_key=asset.key)
        for row in existing:
            mirrored = await self.fetch_mirror(row)
            if mirrored and mirrored.attachments:
                return mirrored.attachments[0].url
        ch = await self.log_channel(guild_id, "media")
        live = asset.replace(size=1024).url
        if not ch or guild_id in self.mirror_off:
            return live
        ext = "gif" if asset.is_animated() else "png"
        try:
            data = await asset.replace(size=1024, format=ext).read()
            emb = discord.Embed(title="🖼️ Avatar snapshot", color=discord.Color.blurple(), timestamp=now_utc(),
                                description=f"{user.mention} (`{user.id}`)\nhash `{asset.key}`")
            emb.set_image(url=f"attachment://avatar.{ext}")
            sent = await ch.send(embed=emb, file=discord.File(io.BytesIO(data), filename=f"avatar.{ext}"))
            url = sent.attachments[0].url
            await store.add_media(guild_id, user.id, None, ch.id, sent.id, "avatar", asset.key)
            return url
        except discord.HTTPException:
            return live

    async def fetch_mirror(self, row):
        channel = self.bot.get_channel(row["channel_id"])
        if not channel or getattr(getattr(channel, "guild", None), "id", None) != row["guild_id"]:
            return None
        try:
            return await channel.fetch_message(row["message_id"])
        except discord.NotFound:
            await store.remove_media(row["id"])
        except discord.HTTPException:
            pass
        return None

    async def refreshed_attachments(self, message_id, guild_id):
        attachments = await db.get_attachments(message_id)
        fresh = {}
        for row in await store.list_media(guild_id=guild_id, original_message_id=message_id, kind="attachment"):
            mirrored = await self.fetch_mirror(row)
            if mirrored:
                fresh.update({a.filename: a.url for a in mirrored.attachments})
        for attachment in attachments:
            # A stored signed CDN URL alone is not a durable reference.
            attachment["mirror_url"] = fresh.get(safe_name(attachment["filename"]))
        return attachments

    async def _erase_media(self, rows):
        removed, failed = 0, 0
        for row in rows:
            channel = self.bot.get_channel(row["channel_id"])
            if not channel or getattr(getattr(channel, "guild", None), "id", None) != row["guild_id"]:
                failed += 1
                continue
            try:
                await channel.get_partial_message(row["message_id"]).delete()
            except discord.NotFound:
                pass
            except discord.HTTPException:
                failed += 1
                continue
            await store.remove_media(row["id"])
            removed += 1
        return {"removed": removed, "failed": failed}

    async def erase_user_media(self, user_id, guild_id=None):
        return await self._erase_media(await store.list_media(guild_id=guild_id, author_id=user_id))

    async def prune_media(self, cutoff, guild_id=None):
        return await self._erase_media(await store.list_media(guild_id=guild_id, before=cutoff))

    # ------------------------------------------------------------ setup / admin commands
    @commands.command(name="setuplogs", aliases=["setlogchannel"])
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def setuplogs(self, ctx, channel: discord.TextChannel):
        """One command: default log channel + every log type on. Saved in the DB, survives restarts."""
        if channel.guild.id != ctx.guild.id:
            return await ctx.send("Choose a log channel in this server.")
        await db.enable_all_logging(ctx.guild.id, channel.id)
        await self.refresh_cache()
        warn = []
        gp = ctx.guild.me.guild_permissions
        for perm, why in (("view_audit_log", "who-did-what logs (roles, moves, bans…)"),
                          ("manage_messages", "scoped delete + compromised-account cleanup"),
                          ("moderate_members", "timeouts for compromised accounts")):
            if not getattr(gp, perm):
                warn.append(f"❌ **{perm.replace('_', ' ')}** missing → {why}")
        cp = channel.permissions_for(ctx.guild.me)
        for perm in ("send_messages", "embed_links", "attach_files"):
            if not getattr(cp, perm):
                warn.append(f"❌ **{perm.replace('_', ' ')}** missing in {channel.mention}")
        await ctx.send(f"📜 All logging enabled → {channel.mention}. Stored in the database; nothing to redo after a restart.\n"
                       f"Route a category elsewhere with `!setlog <category> #channel`, check with `!logstatus`."
                       + ("\n" + "\n".join(warn) if warn else ""))

    @commands.command(name="setlog")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def setlog(self, ctx, category: str, target: str):
        """!setlog <category> <#channel | off | default>"""
        category = category.lower()
        if category not in CATEGORIES:
            return await ctx.send("Categories:\n" + "\n".join(f"`{k}` - {v}" for k, v in CATEGORIES.items()))
        t = target.lower()
        if t == "off":
            await db.set_route(ctx.guild.id, category, 0)
            msg = f"`{category}` logging **disabled**."
        elif t == "default":
            await db.delete_route(ctx.guild.id, category)
            msg = f"`{category}` now follows the default log channel."
        else:
            ch = await commands.TextChannelConverter().convert(ctx, target)
            if ch.guild.id != ctx.guild.id:
                return await ctx.send("Choose a log channel in this server.")
            await db.set_route(ctx.guild.id, category, ch.id)
            msg = f"`{category}` → {ch.mention}"
        await self.refresh_cache()
        await ctx.send("✅ " + msg)

    @commands.command(name="mediamirror")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def mediamirror(self, ctx, state: str):
        """!mediamirror on|off - copy every attachment into the media log channel as it's sent."""
        if state.lower() not in ("on", "off"):
            return await ctx.send("Usage: `!mediamirror on` or `!mediamirror off`")
        await db.set_media_mirror(ctx.guild.id, state.lower() == "on")
        await self.refresh_cache()
        await ctx.send(f"🖼️ Media mirroring **{state.lower()}**.")

    async def _toggle(self, ctx, column: str, label: str):
        state = await db.toggle_log_flag(ctx.guild.id, column)
        if state is None:
            return await ctx.send("~_~ Set a log channel first with `!setuplogs #channel`")
        await ctx.send(f"{label} logging {'enabled ▲' if state else 'disabled △'}")

    @commands.command(name="toggledeletelog")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def toggledeletelog(self, ctx):
        await self._toggle(ctx, "log_deletes", "🗑️ Message delete")

    @commands.command(name="toggleeditlog")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def toggleeditlog(self, ctx):
        await self._toggle(ctx, "log_edits", "✏️ Message edit")

    @commands.command(name="togglebulkdeletelog")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def togglebulkdeletelog(self, ctx):
        await self._toggle(ctx, "log_bulk_deletes", "🧹 Bulk delete")

    @commands.command(name="logstatus")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def logstatus(self, ctx):
        s = await db.get_log_settings(ctx.guild.id)
        default = f"<#{s[0]}>" if s and s[0] else "not set (run `!setuplogs #channel`)"
        lines = []
        for cat in CATEGORIES:
            rid = self.routes.get((ctx.guild.id, cat))
            dest = "disabled" if rid == 0 else f"<#{rid}>" if rid else "default"
            lines.append(f"`{cat:<10}` → {dest}")
        gp = ctx.guild.me.guild_permissions
        checks = [f"{'✅' if getattr(gp, p) else '❌'} {p.replace('_', ' ')}" for p in
                  ("view_audit_log", "manage_messages", "moderate_members", "view_channel")]
        emb = discord.Embed(title="📊 Logging status", color=discord.Color.blurple())
        emb.add_field(name="Default channel", value=default, inline=False)
        emb.add_field(name="Routing", value="\n".join(lines), inline=False)
        emb.add_field(name="Options", value=(f"media mirror: {'off' if ctx.guild.id in self.mirror_off else 'on'}\n"
                                              f"network protection: {'on' if ctx.guild.id in self.network_enabled else 'off'}\n"
                                              f"mode: {'report only' if ctx.guild.id in self.report_only else 'enforce'}\n"
                                              f"media queue: {self.media_queue.qsize()}/{MEDIA_QUEUE_SIZE}; skipped: {self.media_dropped}\n"
                                              "retention: see `!privacysettings`"), inline=False)
        emb.add_field(name="Bot permissions", value="\n".join(checks), inline=False)
        await ctx.send(embed=emb)

    @commands.command(name="protect")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def protect(self, ctx, state: str):
        """!protect on|off - whether this server accepts compromised-account flags from other servers."""
        if state.lower() not in ("on", "off"):
            return await ctx.send("Usage: `!protect on` or `!protect off`")
        await store.set_option(ctx.guild.id, "network_enabled", state.lower() == "on")
        await self.refresh_cache()
        await ctx.send(f"🛡️ Network protection is now **{state.lower()}** for this server. "
                       "Only sources explicitly added with `!trustserver <server-id> on` are accepted.")

    @commands.hybrid_command(name="trustserver")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def trustserver(self, ctx, server_id: str, state: str):
        """Trust or remove a security source. Ordinary server data is never shared."""
        if not server_id.isdigit() or state.lower() not in ("on", "off"):
            return await ctx.send("Usage: `!trustserver <server-id> on|off`")
        source_id = int(server_id)
        if source_id == ctx.guild.id:
            return await ctx.send("Local security does not need network trust.")
        await store.trust(ctx.guild.id, source_id, state.lower() == "on")
        await self.refresh_cache()
        await ctx.send(f"Security trust for `{source_id}` is **{state.lower()}**. "
                       "Receiving security signals also requires `!protect on`.")

    @commands.hybrid_command(name="securitymode")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def securitymode(self, ctx, mode: str):
        """Choose report or enforce for Guardian's automatic security actions."""
        if mode.lower() not in ("report", "enforce"):
            return await ctx.send("Usage: `!securitymode report|enforce`")
        await store.set_option(ctx.guild.id, "report_only", mode.lower() == "report")
        await self.refresh_cache()
        await ctx.send(f"Guardian security mode: **{mode.lower()}**.")

    @commands.hybrid_command(name="patterns")
    @commands.guild_only()
    @commands.has_permissions(moderate_members=True)
    async def patterns(self, ctx):
        """Review security patterns applicable to this server."""
        visible = [p for p in self.fp_cache if self.pattern_applies(p, ctx.guild.id)]
        lines = [f"`{p['id']}` · source `{p['source_guild_id']}` · "
                 f"{len(p['urls'])} exact URL(s), {len(p['shas'])} file hash(es), "
                 f"text {'yes' if p['hash'] else 'no'}" for p in visible[:25]]
        await self.private_response(ctx, content="Security patterns:\n" + ("\n".join(lines) or "None.") +
                                    "\n`!removepattern <id>` removes your server's pattern or ignores an imported one here.")

    @commands.hybrid_command(name="removepattern")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True, moderate_members=True)
    async def removepattern(self, ctx, pattern_id: int):
        """Remove a local pattern or ignore an imported pattern in this server."""
        pattern = next((p for p in self.fp_cache if p["id"] == pattern_id and self.pattern_applies(p, ctx.guild.id)), None)
        if not pattern:
            return await ctx.send("No such security pattern is active in this server.")
        await store.remove_pattern(ctx.guild.id, pattern_id)
        await self.refresh_cache()
        await ctx.send(f"Pattern `{pattern_id}` removed from this server's enforcement.")

    @commands.command(name="forgetuser")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def forgetuser(self, ctx, user_id: int):
        """Administrator: erase a user's stored history and media in this server."""
        copies = await self.erase_user_media(user_id, guild_id=ctx.guild.id)
        await db.forget_user(user_id, guild_id=ctx.guild.id)
        await self.refresh_cache()
        await ctx.send(f"🧽 Erased personal archive data for `{user_id}` in this server. "
                       f"Removed {copies['removed']} mirrored posts; {copies['failed']} could not be removed. "
                       "Active security records are managed separately.")

    # ------------------------------------------------------------ messages + media
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild or message.author.bot:
            return
        deleted = False
        try:
            # Account/text checks run before any storage or media downloads.
            deleted = await self.enforce(message, set())
        except Exception as e:
            print(f"[guardian] enforce error: {e}")
        allowed = await self.archive_allowed(message)
        if allowed:
            try:
                await self.archive(message)
                if deleted:
                    await db.mark_deleted([message.id])
            except Exception as e:
                print(f"[guardian] archive error: {e}")
        if message.attachments and (allowed or self.needs_attachment_scan(message.guild.id)):
            try:
                self.media_queue.put_nowait((message, deleted))
            except asyncio.QueueFull:
                self.media_dropped += 1

    async def archive_allowed(self, message):
        return await self.channel_archive_allowed(message.guild.id, message.channel.id, message.author.id)

    async def channel_archive_allowed(self, guild_id, channel_id, user_id=None):
        channel = self.bot.get_channel(channel_id)
        parents = tuple(x for x in (getattr(channel, "parent_id", None),
                                    getattr(channel, "category_id", None)) if x)
        return await db.should_archive(guild_id, channel_id, user_id, parent_ids=parents)

    def needs_attachment_scan(self, guild_id):
        return any(p["shas"] and self.pattern_applies(p, guild_id) for p in self.fp_cache)

    async def archive(self, message: discord.Message):
        await db.archive_message(self.profile_dict(message.author), {
            "message_id": message.id, "guild_id": message.guild.id, "channel_id": message.channel.id,
            "author_id": message.author.id, "author_name": str(message.author),
            "content": message.content, "content_hash": text_hash(message.content),
            "reply_to_id": message.reference.message_id if message.reference else None,
            "created_at_utc": message.created_at.astimezone(UTC).isoformat(),
        })
        for att in message.attachments:
            await db.add_attachment({
                "message_id": message.id, "guild_id": message.guild.id, "channel_id": message.channel.id,
                "author_id": message.author.id, "filename": att.filename, "url": att.url,
                "mirror_url": None, "sha256": None, "size": att.size, "content_type": att.content_type,
            })

    async def media_worker(self):
        """Only workers download bytes; queue entries hold Discord metadata."""
        while True:
            message, deleted = await self.media_queue.get()
            items = []
            data = None
            try:
                allowed = await self.archive_allowed(message)
                if not allowed and not self.needs_attachment_scan(message.guild.id):
                    continue
                remaining, shas = MAX_READ_BYTES, set()
                for attachment in message.attachments:
                    data = None
                    if attachment.size <= remaining:
                        try:
                            data = await attachment.read()
                        except discord.HTTPException:
                            pass
                        if data is not None:
                            remaining -= len(data)
                            sha = hashlib.sha256(data).hexdigest()
                            shas.add(sha)
                            if allowed:
                                await db._run("UPDATE attachments SET sha256=? WHERE message_id=? AND url=?",
                                              (sha, message.id, attachment.url))
                    items.append((attachment, data))
                if shas and not deleted:
                    await self.enforce(message, shas)
                if allowed and message.guild.id not in self.mirror_off:
                    await self.mirror_media(message, items)
            except Exception as exc:
                print(f"[guardian] media worker error: {exc}")
            finally:
                items.clear()
                data = None
                self.media_queue.task_done()

    async def mirror_media(self, message: discord.Message, items: list):
        async with self.sem:
            try:
                ch = await self.log_channel(message.guild.id, "media")
                if not ch:
                    return
                limit = ch.guild.filesize_limit
                ready, total, skipped = [], 0, []
                for att, data in items:
                    if data is None or total + len(data) > limit:
                        skipped.append(att.filename)
                        continue
                    total += len(data)
                    ready.append((att, data))
                for i in range(0, len(ready), 10):
                    chunk = ready[i:i + 10]
                    files = [discord.File(io.BytesIO(d), filename=safe_name(a.filename)) for a, d in chunk]
                    emb = discord.Embed(color=discord.Color.dark_teal(), timestamp=message.created_at,
                                        title="📎 Attachment copy",
                                        description=short(message.content, 400) or None)
                    emb.add_field(name="Author", value=f"{message.author.mention} (`{message.author.id}`)")
                    emb.add_field(name="Channel", value=f"{message.channel.mention} · [jump]({message.jump_url})")
                    emb.set_footer(text=f"Message ID {message.id}")
                    first_img = next((f for (a, _), f in zip(chunk, files)
                                      if (a.content_type or "").startswith("image/")), None)
                    if first_img:
                        emb.set_image(url=f"attachment://{first_img.filename}")
                    if skipped and i == 0:
                        emb.add_field(name="Not copied (too large / unreadable)", value="\n".join(skipped)[:500], inline=False)
                    sent = await ch.send(embed=emb, files=files)
                    await store.add_media(message.guild.id, message.author.id, message.id,
                                          ch.id, sent.id, "attachment")
                    for (a, _), ma in zip(chunk, sent.attachments):
                        await db.set_attachment_mirror(message.id, a.url, ma.url)
            except Exception as e:
                print(f"[guardian] mirror error: {e}")
            finally:
                items.clear()                         # free memory

    @commands.Cog.listener()
    async def on_raw_message_delete(self, payload: discord.RawMessageDeleteEvent):
        mid = payload.message_id
        row = await db.get_message(mid)
        await db.mark_deleted([mid])
        if mid in self.silent_ids:
            self.silent_ids.discard(mid)
            return
        if not payload.guild_id or payload.channel_id in self.purging:
            return
        if not await self.channel_archive_allowed(payload.guild_id, payload.channel_id,
                                                  row["author_id"] if row else None):
            return
        s = await db.get_log_settings(payload.guild_id)
        if s and not s[1]:
            return
        ch = await self.log_channel(payload.guild_id, "messages")
        if not ch:
            return

        await asyncio.sleep(1.5)                      # let the audit-log entry arrive
        deleter = None
        if row:
            e = self.consume("message_delete", guild_id=payload.guild_id,
                             target=row["author_id"], channel=payload.channel_id, max_age=10)
            deleter = e["actor"] if e else None

        emb = discord.Embed(title="🗑️ Message deleted", color=discord.Color.red(), timestamp=now_utc())
        emb.add_field(name="Channel", value=f"<#{payload.channel_id}>")
        if row:
            emb.add_field(name="Author", value=f"<@{row['author_id']}> (`{row['author_id']}`)")
            emb.add_field(name="Possible moderator", value=f"<@{deleter}> (recent matching audit action; attribution is approximate)" if deleter else "unknown")
            emb.description = short(row["content"], 3500) or "*no text*"
            emb.set_footer(text=f"Message ID {mid} • sent {row['created_at_utc'][:19]} UTC")
            shown = False
            for a in await self.refreshed_attachments(mid, payload.guild_id):
                if a["mirror_url"]:
                    emb.add_field(name="Attachment copy", value=f"[{a['filename']}]({a['mirror_url']})", inline=False)
                    if not shown and (a["content_type"] or "").startswith("image/"):
                        emb.set_image(url=a["mirror_url"])
                        shown = True
                else:
                    emb.add_field(name="Attachment (no copy)", value=a["filename"], inline=False)
        else:
            emb.description = "*Not archived (sent before logging started).*"
        try:
            sent = await ch.send(embed=emb, allowed_mentions=discord.AllowedMentions.none())
            if row:
                await store.add_media(payload.guild_id, row["author_id"], mid, ch.id, sent.id, "message_log")
        except discord.HTTPException:
            pass

    @commands.Cog.listener()
    async def on_raw_bulk_message_delete(self, payload: discord.RawBulkMessageDeleteEvent):
        ids = list(payload.message_ids)
        await db.mark_deleted(ids)
        if not payload.guild_id or payload.channel_id in self.purging:
            return
        if not await self.channel_archive_allowed(payload.guild_id, payload.channel_id):
            return
        s = await db.get_log_settings(payload.guild_id)
        if s and not s[3]:
            return
        ch = await self.log_channel(payload.guild_id, "messages")
        if not ch:
            return
        await ch.send(f"🧹 Bulk delete in <#{payload.channel_id}> - {len(ids)} messages.",
                      allowed_mentions=discord.AllowedMentions.none())

    @commands.Cog.listener()
    async def on_raw_message_edit(self, payload: discord.RawMessageUpdateEvent):
        data = payload.data
        if not payload.guild_id or (data.get("author") or {}).get("bot"):
            return
        if "content" not in data and "attachments" not in data:
            return
        channel = self.bot.get_channel(payload.channel_id)
        if not channel or getattr(getattr(channel, "guild", None), "id", None) != payload.guild_id:
            return
        try:
            message = await channel.fetch_message(payload.message_id)
        except discord.HTTPException:
            return
        if message.author.bot:
            return
        deleted = await self.enforce(message, set())
        allowed = await self.archive_allowed(message)
        if message.attachments and allowed:
            known = {a["url"] for a in await db.get_attachments(message.id)}
            for attachment in message.attachments:
                if attachment.url not in known:
                    await db.add_attachment({"message_id": message.id, "guild_id": message.guild.id,
                        "channel_id": channel.id, "author_id": message.author.id, "filename": attachment.filename,
                        "url": attachment.url, "mirror_url": None, "sha256": None, "size": attachment.size,
                        "content_type": attachment.content_type})
        if message.attachments and (allowed or self.needs_attachment_scan(message.guild.id)):
            try:
                self.media_queue.put_nowait((message, deleted))
            except asyncio.QueueFull:
                self.media_dropped += 1
        if "content" not in data or not allowed:
            return
        new = data["content"]
        row = await db.get_message(payload.message_id)
        old = row["content"] if row else (payload.cached_message.content if payload.cached_message else None)
        if old == new:
            return
        if row:
            await db.log_edit(payload.message_id, old, new, text_hash(new))
        if not payload.guild_id:
            return
        s = await db.get_log_settings(payload.guild_id)
        if s and not s[2]:
            return
        ch = await self.log_channel(payload.guild_id, "messages")
        if not ch:
            return
        author_id = row["author_id"] if row else (data.get("author") or {}).get("id")
        emb = discord.Embed(title="✏️ Message edited", color=discord.Color.orange(), timestamp=now_utc())
        emb.add_field(name="Channel", value=f"<#{payload.channel_id}>")
        if author_id:
            emb.add_field(name="Author", value=f"<@{author_id}> (`{author_id}`)")
        emb.add_field(name="Before", value=f"```{short(old, 900) if old is not None else 'unknown (not archived)'}```", inline=False)
        emb.add_field(name="After", value=f"```{short(new, 900)}```", inline=False)
        emb.set_footer(text=f"Message ID {payload.message_id}")
        sent = await ch.send(embed=emb, allowed_mentions=discord.AllowedMentions.none())
        await store.add_media(payload.guild_id, message.author.id, message.id, ch.id, sent.id, "message_log")

    # ------------------------------------------------------------ joins / leaves / invites
    async def cache_invites(self, guild: discord.Guild):
        try:
            self.invites[guild.id] = {i.code: i for i in await guild.invites()}
        except discord.HTTPException:
            pass                                   # no Manage Server permission -> no invite tracking

    async def detect_invite(self, guild: discord.Guild) -> Optional[discord.Invite]:
        """Which invite did the newcomer use? The one whose use-count went up (or that is new)."""
        before = self.invites.get(guild.id, {})
        try:
            now = {i.code: i for i in await guild.invites()}
        except discord.HTTPException:
            return None
        self.invites[guild.id] = now
        for code, inv in now.items():
            old = before.get(code)
            if old is None or inv.uses > old.uses:
                return inv
        return None

    @commands.Cog.listener()
    async def on_guild_join(self, guild: discord.Guild):
        await self.cache_invites(guild)

    @commands.Cog.listener()
    async def on_guild_remove(self, guild: discord.Guild):
        self.invites.pop(guild.id, None)

    @commands.Cog.listener()
    async def on_invite_create(self, invite: discord.Invite):
        if invite.guild:
            self.invites.setdefault(invite.guild.id, {})[invite.code] = invite

    @commands.Cog.listener()
    async def on_invite_delete(self, invite: discord.Invite):
        if invite.guild:
            self.invites.get(invite.guild.id, {}).pop(invite.code, None)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        guild = member.guild
        flag = self.flag_applies(member.id, guild.id)
        if flag:
            result = await self.apply_timeout(guild, member.id, self.flag_expiry(flag), flag["reason"], flag["source_guild_id"])
            await self.send_log(guild.id, "security", content=f"Flagged account {member.mention} joined: {result}.")
        if not await db.should_archive(guild.id, 0, member.id):
            return
        invite = await self.detect_invite(guild)
        joined = member.joined_at or now_utc()
        await db.record_member_join(guild.id, member.id, member.nick, joined.isoformat(),
                                    invite.code if invite else None,
                                    invite.inviter.id if invite and invite.inviter else None)
        await db.upsert_profile(self.profile_dict(member))
        await self.mirror_avatar(member, guild.id)

        lines = ["**Member joined**",
                 f"{member.mention} {ordinal(guild.member_count)} to join",
                 f"created {human_age(member.created_at, now_utc())}",
                 f"ID: {member.id} • {joined.strftime('%d/%m/%Y %H:%M')}"]
        if invite:
            who = invite.inviter.mention if invite.inviter else "unknown"
            lines.append(f"Invite: `{invite.code}` by {who} (uses: {invite.uses})")
        await self.send_log(guild.id, "members", _subject_id=member.id, content="\n".join(lines))

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member):
        if not await db.should_archive(member.guild.id, 0, member.id):
            return
        await db.mark_member_left(member.guild.id, member.id)
        await self.send_log(member.guild.id, "members", _subject_id=member.id,
                            content=f"**Member left**\n{member.mention}\nID: {member.id}")

    # ------------------------------------------------------------ profile / nickname tracking
    @commands.Cog.listener()
    async def on_user_update(self, before: discord.User, after: discord.User):
        changes = []
        if before.name != after.name:
            changes.append(("username", "Username", before.name, after.name))
        if before.global_name != after.global_name:
            changes.append(("global_name", "Display name", before.global_name, after.global_name))
        old_key = before.avatar.key if before.avatar else None
        new_key = after.avatar.key if after.avatar else None
        if old_key != new_key:
            changes.append(("avatar", "Avatar", old_key, new_key))
        if not changes:
            return
        for g in self.bot.guilds:
            if not g.get_member(after.id) or not await db.should_archive(g.id, 0, after.id):
                continue
            await db.upsert_profile(self.profile_dict(after))
            mirror_url = await self.mirror_avatar(after, g.id) if new_key else None
            for kind, _, old, new in changes:
                await db.add_history(after.id, g.id, kind, old, new, mirror_url if kind == "avatar" else None)
            emb = discord.Embed(title="👤 Profile changed", color=discord.Color.blurple(), timestamp=now_utc(),
                                description=f"{after.mention} (`{after.id}`)")
            for _, label, old, new in changes:
                if label == "Avatar":
                    emb.add_field(name=label, value="thumbnail = before · large image = after", inline=False)
                else:
                    emb.add_field(name=label, value=f"`{old}` → `{new}`", inline=False)
            if old_key != new_key:
                if before.avatar:
                    emb.set_thumbnail(url=before.avatar.replace(size=128).url)
                if mirror_url:
                    emb.set_image(url=mirror_url)
            await self.send_log(g.id, "members", _subject_id=after.id, embed=emb)

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        g = after.guild
        if not await db.should_archive(g.id, 0, after.id):
            return
        if before.nick != after.nick:
            await db.set_member_nick(g.id, after.id, after.nick)
            await db.add_history(after.id, g.id, "nickname", before.nick, after.nick)
            await asyncio.sleep(1.5)
            e = self.find_recent("member_update", guild_id=g.id, target=after.id, key="nick", max_age=15)
            by = f"<@{e['actor']}> (matching audit entry)" if e and e["actor"] else "unknown"
            emb = discord.Embed(title="🏷️ Nickname changed", color=discord.Color.blurple(), timestamp=now_utc(),
                                description=f"{after.mention} (`{after.id}`)\n`{before.nick}` → `{after.nick}`")
            emb.add_field(name="Changed by", value=by)
            await self.send_log(g.id, "members", _subject_id=after.id, embed=emb)
        # fallback only: without View Audit Log we can't say who did it, but still record the change
        if set(before.roles) != set(after.roles) and not g.me.guild_permissions.view_audit_log:
            add = [r.mention for r in after.roles if r not in before.roles]
            rem = [r.mention for r in before.roles if r not in after.roles]
            emb = discord.Embed(title="🎭 Roles changed (actor unknown)", color=discord.Color.gold(), timestamp=now_utc(),
                                description=f"{after.mention} (`{after.id}`)")
            if add:
                emb.add_field(name="Added", value=", ".join(add))
            if rem:
                emb.add_field(name="Removed", value=", ".join(rem))
            emb.set_footer(text="Give the bot View Audit Log to see who did it")
            await self.send_log(g.id, "roles", _subject_id=after.id, embed=emb)

    # ------------------------------------------------------------ voice
    @commands.Cog.listener()
    async def on_voice_state_update(self, member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
        g = member.guild
        if not await db.should_archive(g.id, 0, member.id):
            return
        b, a = before.channel, after.channel
        if b != a:
            if b and a:
                await asyncio.sleep(1.5)
                # Discord's aggregate move entries do not identify each moved member.
                e = None
                emb = discord.Embed(title="🎤 Voice: moved", color=discord.Color.teal(), timestamp=now_utc(),
                                    description=f"{member.mention} (`{member.id}`)\n{b.mention} → {a.mention}")
                emb.add_field(name="Moved by", value="unknown (Discord does not identify the member in move audit entries)")
            elif a:
                emb = discord.Embed(title="🎤 Voice: joined", color=discord.Color.green(), timestamp=now_utc(),
                                    description=f"{member.mention} (`{member.id}`) → {a.mention}")
            else:
                await asyncio.sleep(1.5)
                e = None
                emb = discord.Embed(title="🎤 Voice: left", color=discord.Color.dark_grey(), timestamp=now_utc(),
                                    description=f"{member.mention} (`{member.id}`) ← {b.mention}")
                emb.add_field(name="Disconnected by", value="unknown (self, connection loss, or moderator)")
            await self.send_log(g.id, "voice", _subject_id=member.id, embed=emb)
            return
        if a is None:
            return
        notes = []
        if before.self_stream != after.self_stream:
            notes.append("started streaming 🔴" if after.self_stream else "stopped streaming")
        if before.self_video != after.self_video:
            notes.append("camera on 📷" if after.self_video else "camera off")
        if notes:
            await self.send_log(g.id, "voice", _subject_id=member.id, embed=discord.Embed(
                title="🎤 Voice activity", color=discord.Color.teal(), timestamp=now_utc(),
                description=f"{member.mention} {', '.join(notes)} in {a.mention}"))

    # ------------------------------------------------------------ audit log (who did what to whom)
    @commands.Cog.listener()
    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry):
        try:
            await self.handle_audit(entry)
        except Exception as e:
            print(f"[guardian] audit error: {e}")

    def category_for(self, name: str) -> str:
        if name in ("member_role_update", "role_create", "role_update", "role_delete") or name.startswith("overwrite_"):
            return "roles"
        if name in ("kick", "ban", "unban", "member_prune", "member_update") or "automod" in name or "auto_moderation" in name:
            return "moderation"
        return "server"

    async def handle_audit(self, entry: discord.AuditLogEntry):
        act = entry.action.name
        before, after = dict(iter(entry.before)), dict(iter(entry.after))
        extra = entry.extra
        rec = {"guild_id": entry.guild.id, "ts": time.monotonic(), "action": act, "actor": entry.user_id, "target": target_id_of(entry),
               "channel": getattr(getattr(extra, "channel", None), "id", None),
               "left": getattr(extra, "count", 1) or 1, "keys": set(before) | set(after)}
        self.audit_buf.append(rec)

        if act in AUDIT_MERGED or entry.user_id == getattr(self.bot.user, "id", None):
            return
        emb = self.build_audit_embed(entry, before, after)
        try:
            await db.add_audit_event(entry.guild.id, act, entry.user_id, target_id_of(entry),
                                     f"{emb.title} {short(emb.description or '', 200)}")
        except Exception:
            pass
        if act == "member_update" and rec["keys"] <= {"nick"}:
            return                                  # nickname logs come from on_member_update (with actor)
        await self.send_log(entry.guild.id, self.category_for(act), embed=emb)

    def build_audit_embed(self, entry, before: dict, after: dict) -> discord.Embed:
        act = entry.action.name
        title = f"{ICONS.get(act, '📋')} {act.replace('_', ' ').title()}"
        emb = discord.Embed(title=title, color=discord.Color.dark_gold(), timestamp=entry.created_at)
        emb.add_field(name="By", value=fmt_ref(entry.user, entry.user_id))
        tid = target_id_of(entry)
        if entry.target is not None or tid:
            emb.add_field(name="Target", value=fmt_ref(entry.target, tid))
        extra = entry.extra
        if act.startswith("overwrite_") and extra is not None:
            emb.add_field(name="Applies to", value=fmt_ref(extra))
        if act == "member_role_update":
            added, removed = after.get("roles", []), before.get("roles", [])
            if added:
                emb.add_field(name="➕ Role given", value=", ".join(fmt_ref(r) for r in added)[:1000], inline=False)
            if removed:
                emb.add_field(name="➖ Role removed", value=", ".join(fmt_ref(r) for r in removed)[:1000], inline=False)
        for label, key in (("Permissions (➕ granted / ➖ revoked)", "permissions"), ("Explicitly ALLOWED (➕ added / ➖ removed)", "allow"), ("Explicitly DENIED (➕ added / ➖ removed)", "deny")):
            if key in before or key in after:
                txt = perm_lines(label, before.get(key), after.get(key))
                if txt:
                    emb.add_field(name=label, value=txt[:1000], inline=False)
        lines = []
        for k in sorted(set(before) | set(after)):
            if k in ("roles", "permissions", "allow", "deny"):
                continue
            o, n = before.get(k), after.get(k)
            if o == n:
                continue
            nice = k.replace("_", " ")
            if o is not None and n is not None:
                lines.append(f"**{nice}:** {fmt_val(o)} → {fmt_val(n)}")
            elif n is None:
                lines.append(f"**{nice}:** cleared (was {fmt_val(o)})")
            else:
                lines.append(f"**{nice}:** {fmt_val(n)}")
        if lines:
            emb.add_field(name="Changes", value="\n".join(lines[:15])[:1000], inline=False)
        if entry.reason:
            emb.add_field(name="Reason", value=short(entry.reason, 300), inline=False)
        emb.set_footer(text=f"Audit entry {entry.id}")
        return emb

    # ------------------------------------------------------------ scoped purge
    @commands.command(name="alarmbot")
    @commands.guild_only()
    async def alarmbot(self, ctx, *, raw: str = ""):
        """!alarmbot -d -u @user [@user2 | all] -t 1H -c #chan1 #chan2"""
        usage = ("**Usage:** `!alarmbot -d -u @user -t 1H -c #welcome #general`\n"
                 "`-d` delete · `-u` users (mentions/IDs/names, or `all`) · "
                 "`-t` time (`30m` `1H` `2d` `1w` `6mo` `1y` `1d12h` or `all`) · "
                 "`-c` channels (omit = this channel, `all` = every channel)")
        if not ctx.author.guild_permissions.manage_messages:
            return await ctx.send("~_~ You need **Manage Messages** for that.")
        flags = parse_flags(raw)
        if "d" not in flags:
            return await ctx.send(usage)
        if "u" not in flags or not flags["u"]:
            return await ctx.send("~_~ Add `-u @user` (or `-u all`).\n" + usage)
        user_ids, utxt = None, flags["u"].split()
        if [t.lower() for t in utxt] != ["all"]:
            user_ids = set()
            for t in utxt:
                m = ID_RE.fullmatch(t)
                if m:
                    user_ids.add(int(m.group(1) or m.group(2)))
                    continue
                name = t.lstrip("@").lower()
                mem = discord.utils.find(lambda x: name in (x.name.lower(), x.display_name.lower(),
                                                             (x.global_name or "").lower()), ctx.guild.members)
                if not mem:
                    return await ctx.send(f"~_~ Couldn't find user `{t}`. Use a mention or their ID.")
                user_ids.add(mem.id)

        span = parse_span(flags.get("t", ""))
        if span is None:
            return await ctx.send("~_~ Add a valid time, e.g. `-t 1H`, `-t 2d`, `-t 1w`, `-t 1y`, `-t all`.\n" + usage)
        cutoff = None if span == "all" else now_utc() - span

        channels, ctext = [], flags.get("c", "").split()
        if not ctext:
            channels = [ctx.channel]
        elif [t.lower() for t in ctext] == ["all"]:
            channels = list(ctx.guild.text_channels) + list(ctx.guild.threads)
        else:
            for t in ctext:
                m = ID_RE.fullmatch(t)
                ch = ctx.guild.get_channel_or_thread(int(m.group(1) or m.group(2))) if m else \
                    discord.utils.get(ctx.guild.text_channels, name=t.lstrip("#").lower())
                if ch is None:
                    return await ctx.send(f"~_~ Couldn't find channel `{t}`.")
                if isinstance(ch, discord.CategoryChannel):
                    channels.extend(ch.text_channels)
                else:
                    channels.append(ch)
        channels = [c for c in dict.fromkeys(channels) if hasattr(c, "purge")]

        usable, skipped = [], []
        for ch in channels:
            me_p, u_p = ch.permissions_for(ctx.guild.me), ch.permissions_for(ctx.author)
            if not (u_p.view_channel and u_p.read_message_history and u_p.manage_messages):
                skipped.append(f"{ch.mention} (you lack channel access / history / Manage Messages)")
            elif not (me_p.view_channel and me_p.read_message_history and me_p.manage_messages):
                skipped.append(f"{ch.mention} (bot lacks permissions)")
            else:
                usable.append(ch)
        if not usable:
            return await ctx.send("~_~ Nothing to do.\n" + "\n".join(skipped))

        who = "**everyone**" if user_ids is None else ", ".join(f"<@{i}>" for i in sorted(user_ids))
        when = "**all history**" if cutoff is None else f"the last **{flags['t']}**"
        summary = f"Delete messages from {who} in {when} across {len(usable)} channel(s)?"

        if user_ids is None or cutoff is None or (len(ctext) == 1 and ctext[0].lower() == "all"):
            view = Confirm(ctx.author.id)
            status = await ctx.send(summary, view=view)
            await view.wait()
            if not view.value:
                return await status.edit(content="Cancelled.", view=None)
            await status.edit(content="⏳ Deleting…", view=None)
        else:
            status = await ctx.send("⏳ Deleting…")

        actor = ctx.author

        def check(m: discord.Message) -> bool:
            member = ctx.guild.get_member(m.author.id)
            hierarchy_ok = member is None or member.id == actor.id or can_moderate(actor, member, ctx.guild)
            return hierarchy_ok and m.id != status.id and (user_ids is None or m.author.id in user_ids)

        total, per_channel = 0, []
        for ch in usable:
            # A confirmation may remain open while the moderator's roles or
            # channel permissions change. Recheck authority at execution.
            try:
                actor = await ctx.guild.fetch_member(ctx.author.id)
            except discord.HTTPException:
                skipped.append(f"{ch.mention} (could not confirm your membership)")
                break
            current_channel = ctx.guild.get_channel_or_thread(ch.id)
            if current_channel is None:
                skipped.append(f"{ch.mention} (channel no longer available)")
                continue
            ch = current_channel
            me_p, u_p = ch.permissions_for(ctx.guild.me), ch.permissions_for(actor)
            if not (u_p.view_channel and u_p.read_message_history and u_p.manage_messages
                    and me_p.view_channel and me_p.read_message_history and me_p.manage_messages):
                skipped.append(f"{ch.mention} (permissions changed)")
                continue
            self.purging.add(ch.id)
            try:
                deleted = await ch.purge(limit=None, after=cutoff, check=check, bulk=True)
                await db.mark_deleted([m.id for m in deleted])
                total += len(deleted)
                per_channel.append(f"{ch.mention}: {len(deleted)}")
            except discord.HTTPException as e:
                per_channel.append(f"{ch.mention}: failed ({e.status})")
            finally:
                self.purging.discard(ch.id)

        await db.add_purge_audit(ctx.guild.id, ctx.author.id, raw, total)
        report = f"✅ Deleted **{total}** message(s).\n" + "\n".join(per_channel[:25])
        if skipped:
            report += "\nSkipped: " + ", ".join(skipped[:10])
        try:
            await status.edit(content=report[:1900], view=None)
        except discord.HTTPException:
            await ctx.send(report[:1900])
        await self.send_log(ctx.guild.id, "moderation",
                            content=f"🧹 {ctx.author.mention} ran `!alarmbot {raw[:300]}` - {total} deleted.")

    # ------------------------------------------------------------ compromised accounts
    def can_receive_security(self, source_gid: int, target_gid: int) -> bool:
        return source_gid == target_gid or (
            target_gid in self.network_enabled and (target_gid, source_gid) in self.trusted_sources)

    async def security_allowed(self, source_gid: int, target_gid: int) -> bool:
        return self.can_receive_security(source_gid, target_gid)

    async def publish_security_alert(self, source_gid: int, content: str, *, source="security", include_source=False):
        """Forward security-only summaries to explicitly trusting recipients."""
        for guild in self.bot.guilds:
            if guild.id == source_gid and not include_source:
                continue
            if self.can_receive_security(source_gid, guild.id):
                await self.send_log(guild.id, "security", content=(
                    f"Security signal from server `{source_gid}` ({short(source, 40)}):\n{short(content, 1700)}"))

    def applicable_flags(self, uid: int, gid: int):
        now = now_utc()
        return [flag for (source_gid, user_id), flag in self.flagged.items()
                if user_id == uid and self.can_receive_security(source_gid, gid)
                and (gid, source_gid, uid) not in self.exempt
                and (self.flag_expiry(flag) is None or self.flag_expiry(flag) > now)]

    def flag_applies(self, uid: int, gid: int):
        flags = self.applicable_flags(uid, gid)
        return max(flags, key=lambda f: self.flag_expiry(f) or datetime.max.replace(tzinfo=UTC), default=None)

    def pattern_applies(self, pattern, gid: int):
        source_gid = pattern["source_guild_id"]
        flag = self.flagged.get((source_gid, pattern["user_id"]))
        return (flag is not None and self.can_receive_security(source_gid, gid)
                and (gid, source_gid, pattern["user_id"]) not in self.exempt
                and (gid, pattern["id"]) not in self.pattern_exempt
                and (self.flag_expiry(flag) is None or self.flag_expiry(flag) > now_utc()))

    @staticmethod
    def flag_expiry(flag) -> Optional[datetime]:
        return datetime.fromisoformat(flag["expires_at_utc"]) if flag["expires_at_utc"] else None

    async def apply_timeout(self, guild, uid, expires, reason, source_gid=None):
        flag = self.flag_applies(uid, guild.id)
        source_gid = source_gid if source_gid is not None else (flag["source_guild_id"] if flag else guild.id)
        if not self.can_receive_security(source_gid, guild.id) or (guild.id, source_gid, uid) in self.exempt:
            return "not accepted by this server"
        if guild.id in self.report_only:
            return "report only; no timeout applied"
        me = guild.me
        if not me.guild_permissions.moderate_members:
            return "bot lacks Moderate Members"
        until = min(expires, now_utc() + MAX_TIMEOUT) if expires else now_utc() + MAX_TIMEOUT
        if until <= now_utc():
            return "flag expired"
        async with self._timeout_locks.setdefault((guild.id, uid), asyncio.Lock()):
            # Cached member state can lag a moderator's edit. Read Discord before
            # recording the prior timeout so we can restore the real value.
            try:
                member = await guild.fetch_member(uid)
            except discord.NotFound:
                return "not a member"
            except discord.HTTPException as exc:
                return f"failed to refresh member ({exc.status})"
            if member.guild_permissions.administrator or member.id == guild.owner_id or member.top_role >= me.top_role:
                return "cannot time out (administrator / role hierarchy)"
            current = member.timed_out_until
            if current and current >= until - timedelta(seconds=1):
                return "existing timeout retained"
            record = await store.timeout_record(guild.id, uid)
            previous = record["previous_until"] if record and same_timeout(current, record["applied_until"]) else (
                current.isoformat() if current and current > now_utc() else None)
            try:
                await member.timeout(until, reason=f"Compromised-account protection: {reason}"[:500])
            except discord.HTTPException as exc:
                return f"failed ({exc.status})"
            await store.save_timeout(guild.id, uid, source_gid, previous, until.isoformat())
            return "timed out"

    async def release_owned_timeout(self, guild, uid):
        """Restore only our unchanged timeout, preserving all unrelated moderation."""
        async with self._timeout_locks.setdefault((guild.id, uid), asyncio.Lock()):
            record = await store.timeout_record(guild.id, uid)
            if not record or (guild.id not in self.report_only and self.flag_applies(uid, guild.id)):
                return False
            if not guild.me.guild_permissions.moderate_members:
                return False
            try:
                member = await guild.fetch_member(uid)
            except discord.NotFound:
                await store.remove_timeout(guild.id, uid)
                return False
            except discord.HTTPException:
                return False
            if not same_timeout(member.timed_out_until, record["applied_until"]):
                # Someone else changed the timeout after us. It is theirs now.
                await store.remove_timeout(guild.id, uid)
                return False
            previous = datetime.fromisoformat(record["previous_until"]) if record["previous_until"] else None
            if previous and previous <= now_utc():
                previous = None
            try:
                await member.timeout(previous, reason="Guardian flag ended; restoring prior timeout")
            except discord.HTTPException:
                return False
            await store.remove_timeout(guild.id, uid)
            return True

    @commands.hybrid_command(name="compromised", aliases=["hacked"])
    @commands.guild_only()
    @commands.has_guild_permissions(manage_messages=True, moderate_members=True)
    async def compromised(self, ctx, user: Optional[discord.User] = None, duration: str = "24h",
                          *, reason: str = "Account compromised"):
        """Flag a local account; replying confirms that message as scam evidence."""
        if getattr(ctx, "interaction", None):
            await ctx.defer(ephemeral=True)
        target_msg = None
        ref = getattr(ctx.message, "reference", None)
        if ref and ref.message_id:
            try:
                target_msg = await ctx.channel.fetch_message(ref.message_id)
            except discord.HTTPException:
                pass
        if user is None and target_msg:
            user = target_msg.author
        if user is None:
            return await ctx.send("Reply to confirmed scam evidence with `!compromised`, or use "
                                  "`!compromised @user [24h|7d|perm] [reason]`. No patterns are learned without a reply.")
        member = ctx.guild.get_member(user.id)
        if user.bot or not can_moderate(ctx.author, member, ctx.guild):
            return await ctx.send("You can only flag a current member below your role in this server; "
                                  "you cannot flag yourself or the server owner.")
        if target_msg and target_msg.author.id != user.id:
            return await ctx.send("The replied message must belong to the account you are flagging.")
        if duration.lower() in ("perm", "permanent", "manual"):
            expires = None
        else:
            span = parse_span(duration)
            if span in (None, "all"):
                return await ctx.send("Duration must be like `24h`, `7d`, `2w`, or `perm`.")
            expires = now_utc() + span
        await store.flag(ctx.guild.id, user.id, ctx.author.id, reason[:300], expires.isoformat() if expires else None)
        made = 0
        if target_msg:
            shas = {a["sha256"] for a in await db.get_attachments(target_msg.id) if a["sha256"]}
            # Evidence may not be archived, so hash selected attachments within a fixed byte budget.
            remaining = MAX_READ_BYTES
            for attachment in target_msg.attachments:
                if attachment.size <= remaining:
                    try:
                        evidence = await attachment.read()
                    except discord.HTTPException:
                        continue
                    remaining -= len(evidence)
                    shas.add(hashlib.sha256(evidence).hexdigest())
                    del evidence
            content_hash, urls = text_hash(target_msg.content), urls_of(target_msg.content)
            if content_hash or urls or shas:
                await store.add_pattern(ctx.guild.id, user.id, content_hash, urls, shas,
                                        norm_text(target_msg.content), target_msg.id)
                made = 1
        await self.refresh_cache()
        deleted_ids = []
        # Historical cleanup is strictly local. Trusted receivers apply their own incoming-message policy.
        rows = await db.recent_messages_by_author(user.id, (now_utc() - timedelta(hours=1)).isoformat(), 200,
                                                 guild_id=ctx.guild.id)
        if target_msg and not any(row["message_id"] == target_msg.id for row in rows):
            rows.append({"message_id": target_msg.id, "channel_id": ctx.channel.id, "guild_id": ctx.guild.id})
        if ctx.guild.id not in self.report_only:
            for row in rows:
                channel = ctx.guild.get_channel_or_thread(row["channel_id"])
                if not channel:
                    continue
                perms = channel.permissions_for(ctx.author)
                if not (perms.view_channel and perms.manage_messages):
                    continue
                self.silent_ids.add(row["message_id"])
                try:
                    await channel.get_partial_message(row["message_id"]).delete()
                except discord.HTTPException:
                    self.silent_ids.discard(row["message_id"])
                    continue
                deleted_ids.append(row["message_id"])
            await db.mark_deleted(deleted_ids)
        local_result = "not applied"
        for guild in self.bot.guilds:
            # Existing flags from a different source must not expose this
            # command's reason to a server that never trusted its source.
            if not self.can_receive_security(ctx.guild.id, guild.id) or (guild.id, ctx.guild.id, user.id) in self.exempt:
                continue
            flag = self.flag_applies(user.id, guild.id)
            if not flag or not guild.get_member(user.id):
                continue
            result = await self.apply_timeout(guild, user.id, self.flag_expiry(flag), flag["reason"], flag["source_guild_id"])
            if guild.id == ctx.guild.id:
                local_result = result
            await self.send_log(guild.id, "security", content=(
                f"Compromised account `{user.id}` flagged by source server `{ctx.guild.id}`. "
                f"Reason: {short(reason, 300)}. Result here: {result}."))
        await ctx.send(f"Flag saved for `{user.id}`. Local result: **{local_result}**. "
                       f"Removed {len(deleted_ids)} local message(s); learned {made} confirmed pattern(s). "
                       "Only explicitly trusting servers with protection enabled can accept this security flag.")

    @commands.hybrid_command(name="uncompromised", aliases=["clearflag"])
    @commands.guild_only()
    @commands.has_guild_permissions(manage_messages=True, moderate_members=True)
    async def uncompromised(self, ctx, user: discord.User):
        """Clear this server's flag and locally exempt accepted external flags."""
        member = ctx.guild.get_member(user.id)
        local_flag = self.flagged.get((ctx.guild.id, user.id))
        if member and not can_moderate(ctx.author, member, ctx.guild):
            return await ctx.send("That account is outside your moderation role hierarchy.")
        if member is None and local_flag is None:
            return await ctx.send("No local member or local flag exists for that account.")
        flags = self.applicable_flags(user.id, ctx.guild.id)
        if not flags and not local_flag:
            return await ctx.send("No active flag applies to that account here.")
        if local_flag:
            await store.clear_flag(ctx.guild.id, user.id)
        for flag in flags:
            if flag["source_guild_id"] != ctx.guild.id:
                await store.exempt(ctx.guild.id, flag["source_guild_id"], user.id)
        await self.refresh_cache()
        for guild in self.bot.guilds:
            if guild.id == ctx.guild.id or (local_flag and self.can_receive_security(ctx.guild.id, guild.id)):
                await self.release_owned_timeout(guild, user.id)
        await ctx.send(f"Cleared this server's flag for `{user.id}` and ignored currently accepted external flags here. "
                       "Only unchanged timeouts owned by Guardian can be restored.")

    @commands.hybrid_command(name="flagged")
    @commands.guild_only()
    @commands.has_guild_permissions(moderate_members=True)
    async def flagged_list(self, ctx):
        lines = []
        for flag in self.flagged.values():
            if not ctx.guild.get_member(flag["user_id"]) or flag not in self.applicable_flags(flag["user_id"], ctx.guild.id):
                continue
            expires = self.flag_expiry(flag)
            end = f"<t:{int(expires.timestamp())}:R>" if expires else "manual clearance"
            lines.append(f"`{flag['user_id']}` · source `{flag['source_guild_id']}` · {end} · {short(flag['reason'], 80)}")
        await self.private_response(ctx, embed=discord.Embed(title="Security flags applicable here",
            description="\n".join(lines[:25]) or "None.", color=discord.Color.dark_red()))

    async def enforce(self, message, shas: set):
        uid, gid = message.author.id, message.guild.id
        flag = self.flag_applies(uid, gid)
        reason = "flagged compromised account" if flag else self.match_fingerprint(message, shas)
        if not reason:
            return False
        if gid in self.report_only:
            key = (gid, message.id)
            if key not in self._notice_times:
                self._notice_times[key] = time.monotonic()
                await self.send_log(gid, "security", content=(
                    f"Report only: message `{message.id}` from `{uid}` in {message.channel.mention}: {reason}. No action taken."))
            return False
        # Respect Discord's protected roles even for automatic security actions.
        member = message.author
        if member.id == message.guild.owner_id or member.guild_permissions.administrator or member.top_role >= message.guild.me.top_role:
            return False
        self.silent_ids.add(message.id)
        try:
            await message.delete()
        except discord.HTTPException:
            self.silent_ids.discard(message.id)
            return False
        await db.mark_deleted([message.id])
        if flag:
            await self.apply_timeout(message.guild, uid, self.flag_expiry(flag), flag["reason"], flag["source_guild_id"])
        await self.send_log(gid, "security", content=(
            f"Deleted message `{message.id}` from `{uid}` in {message.channel.mention}: {reason}."))
        return True

    def match_fingerprint(self, message, shas: set) -> Optional[str]:
        content_hash, urls = text_hash(message.content), urls_of(message.content)
        for pattern in self.fp_cache:
            if not self.pattern_applies(pattern, message.guild.id):
                continue
            if content_hash and content_hash == pattern["hash"]:
                return f"matches confirmed scam text (pattern {pattern['id']})"
            if urls & pattern["urls"]:
                return f"contains a confirmed scam URL (pattern {pattern['id']})"
            if shas & pattern["shas"]:
                return f"contains a confirmed scam attachment (pattern {pattern['id']})"
        return None

    @tasks.loop(seconds=60)
    async def enforce_loop(self):
        try:
            await store.expire_flags()
            await self.refresh_cache()
            for record in await db._all("SELECT * FROM guardian_timeouts"):
                guild = self.bot.get_guild(record["guild_id"])
                if guild:
                    await self.release_owned_timeout(guild, record["user_id"])
            for guild in self.bot.guilds:
                for uid in {flag["user_id"] for flag in self.flagged.values()}:
                    member = guild.get_member(uid)
                    flag = self.flag_applies(uid, guild.id)
                    if member is None or flag is None:
                        continue
                    expires = self.flag_expiry(flag)
                    desired = min(expires, now_utc() + MAX_TIMEOUT) if expires else now_utc() + MAX_TIMEOUT
                    if member.timed_out_until is None or member.timed_out_until < desired - timedelta(minutes=5):
                        await self.apply_timeout(guild, uid, expires, flag["reason"], flag["source_guild_id"])
            self._notice_times = {key: stamp for key, stamp in self._notice_times.items() if time.monotonic() - stamp < 300}
            self.silent_ids.clear()
        except Exception as exc:
            print(f"[guardian] enforce loop error: {exc}")

    @enforce_loop.before_loop
    async def _before_enforce(self):
        await self.bot.wait_until_ready()

    async def private_response(self, ctx, **kwargs):
        kwargs.setdefault("allowed_mentions", discord.AllowedMentions.none())
        if getattr(ctx, "interaction", None):
            return await ctx.send(ephemeral=True, **kwargs)
        try:
            await ctx.author.send(**kwargs)
        except discord.HTTPException:
            return await ctx.send("I could not send your private result. Enable DMs or use the slash command.")
        await ctx.send("Sent the result privately.", delete_after=10)

    # ------------------------------------------------------------ strictly local investigation
    @commands.hybrid_command(name="userinfo", aliases=["whois", "trace"])
    @commands.guild_only()
    @commands.has_guild_permissions(moderate_members=True)
    async def userinfo(self, ctx, user: discord.User):
        member = ctx.guild.get_member(user.id)
        if member is None:
            return await ctx.send("Choose a current member of this server.")
        if getattr(ctx, "interaction", None):
            await ctx.defer(ephemeral=True)
        emb = discord.Embed(title=f"Member information: {member}", color=discord.Color.blurple(), timestamp=now_utc())
        emb.set_thumbnail(url=member.display_avatar.url)
        emb.add_field(name="ID", value=f"`{member.id}`")
        emb.add_field(name="Account created", value=f"<t:{int(member.created_at.timestamp())}:F>")
        if member.joined_at:
            emb.add_field(name="Joined this server", value=f"<t:{int(member.joined_at.timestamp())}:F>")
        emb.add_field(name="Nickname here", value=short(member.nick or "none", 100))
        flag = self.flag_applies(member.id, ctx.guild.id)
        if flag:
            emb.add_field(name="Applicable security flag", value=short(flag["reason"], 100))
        if await db.should_archive(ctx.guild.id, 0, member.id):
            emb.add_field(name="Messages archived here", value=str(await db.count_messages(member.id, ctx.guild.id)))
            history = await db.get_history(member.id, ctx.guild.id, 12)
            if history:
                lines = [f"`{row['changed_at_utc'][:10]}` {row['kind']}: "
                         f"{short(row['old_value'], 70)} → {short(row['new_value'], 70)}" for row in history]
                emb.add_field(name="History observed in this server", value="\n".join(lines)[:1000], inline=False)
            events = await db.get_audit_events(member.id, ctx.guild.id, 6)
            if events:
                lines = [f"`{row['created_at_utc'][:10]}` {row['action'].replace('_', ' ')}" for row in events]
                emb.add_field(name="Staff actions in this server", value="\n".join(lines)[:1000], inline=False)
            signals = await db.alt_signals(member.id, ctx.guild.id)
            matches = []
            for uid, reasons in sorted(signals.items(), key=lambda pair: sum(weight for _, weight in pair[1]), reverse=True):
                if ctx.guild.get_member(uid) is None or not await db.should_archive(ctx.guild.id, 0, uid):
                    continue
                score = sum(weight for _, weight in reasons)
                if score >= 25:
                    matches.append(f"`{uid}`: " + "; ".join(reason for reason, _ in reasons))
                if len(matches) == 6:
                    break
            emb.add_field(name="Similarities within this server — not proof of alternate accounts",
                          value="\n".join(matches)[:1000] or "Nothing notable.", inline=False)
        await self.private_response(ctx, embed=emb)


async def setup(bot: commands.Bot):
    await bot.add_cog(Guardian(bot))
