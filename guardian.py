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
import os
import re
import time
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from typing import Optional

import discord
import pytz
from dateutil.relativedelta import relativedelta
from discord.ext import commands, tasks

import database as db

UTC = pytz.UTC
MAX_READ_BYTES = 25 * 1024 * 1024
MAX_TIMEOUT = timedelta(days=27, hours=23)          # Discord caps a timeout at 28 days
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "0") or 0)

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
        self.exempt: dict = {}
        self.protect_off: set = set()
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

    # ------------------------------------------------------------ lifecycle
    async def cog_load(self):
        await self.refresh_cache()
        self.enforce_loop.start()
        self.retention_loop.start()

    async def cog_unload(self):
        self.enforce_loop.cancel()
        self.retention_loop.cancel()

    async def refresh_cache(self):
        self.flagged = {f["user_id"]: f for f in await db.get_active_flags()}
        self.exempt = {}
        for e in await db.get_exempts():
            self.exempt.setdefault(e["user_id"], set()).add(e["guild_id"])
        self.protect_off = await db.get_protection_off()
        self.mirror_off = await db.get_mirror_off()
        self.routes = await db.get_routes()
        self.fp_cache = []
        for f in await db.get_fingerprints():
            self.fp_cache.append({
                "user_id": f["user_id"], "hash": f["content_hash"], "norm": f["sample"] or "",
                "domains": set(filter(None, (f["domains"] or "").split(","))),
                "shas": set(filter(None, (f["attachment_shas"] or "").split(","))),
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
            changed = await db.sync_profiles(profiles, members)
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
            return self.bot.get_channel(rid)
        s = await db.get_log_settings(guild_id)
        return self.bot.get_channel(s[0]) if s and s[0] else None

    async def send_log(self, guild_id: int, category: str, **kw):
        ch = await self.log_channel(guild_id, category)
        if ch:
            try:
                return await ch.send(**kw)
            except discord.HTTPException:
                pass
        return None

    def spawn(self, coro):
        t = asyncio.create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def is_owner(self, user) -> bool:
        return await self.bot.is_owner(user)

    def consume(self, action: str, *, target=None, channel=None, max_age=15):
        """Find (and use up one count of) a recent audit entry. Used to attribute moves/disconnects."""
        now = time.monotonic()
        for e in reversed(self.audit_buf):
            if e["action"] != action or now - e["ts"] > max_age or e["left"] <= 0:
                continue
            if target is not None and e["target"] != target:
                continue
            if channel is not None and e["channel"] != channel:
                continue
            e["left"] -= 1
            return e
        return None

    def find_recent(self, action: str, *, target=None, channel=None, key=None, max_age=15):
        now = time.monotonic()
        for e in reversed(self.audit_buf):
            if e["action"] != action or now - e["ts"] > max_age:
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
        existing = await db.get_avatar_mirror(user.id, asset.key)
        if existing:
            return existing
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
            await db.add_avatar_mirror(user.id, asset.key, url)
            return url
        except discord.HTTPException:
            return live

    # ------------------------------------------------------------ setup / admin commands
    @commands.command(name="setuplogs", aliases=["setlogchannel"])
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def setuplogs(self, ctx, channel: discord.TextChannel):
        """One command: default log channel + every log type on. Saved in the DB, survives restarts."""
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
                                              f"network protection: {'off' if ctx.guild.id in self.protect_off else 'on'}\n"
                                              f"retention: {RETENTION_DAYS or 'forever'} days"), inline=False)
        emb.add_field(name="Bot permissions", value="\n".join(checks), inline=False)
        await ctx.send(embed=emb)

    @commands.command(name="protect")
    @commands.guild_only()
    @commands.has_permissions(administrator=True)
    async def protect(self, ctx, state: str):
        """!protect on|off - whether this server accepts compromised-account flags from other servers."""
        if state.lower() not in ("on", "off"):
            return await ctx.send("Usage: `!protect on` or `!protect off`")
        await db.set_protection(ctx.guild.id, state.lower() == "on")
        await self.refresh_cache()
        await ctx.send(f"🛡️ Network protection is now **{state.lower()}** for this server.")

    @commands.command(name="forgetuser")
    @commands.is_owner()
    async def forgetuser(self, ctx, user_id: int):
        """Bot owner only: erase everything stored about a user ID (mirrored copies in log channels stay)."""
        await db.forget_user(user_id)
        await self.refresh_cache()
        await ctx.send(f"🧽 Erased stored data for `{user_id}`.")

    # ------------------------------------------------------------ messages + media
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if not message.guild or message.author.bot:
            return
        shas, items = set(), []
        try:
            shas, items = await self.archive(message)
        except Exception as e:
            print(f"[guardian] archive error: {e}")
        try:
            await self.enforce(message, shas)
        except Exception as e:
            print(f"[guardian] enforce error: {e}")
        if items and message.guild.id not in self.mirror_off:
            self.spawn(self.mirror_media(message, items))

    async def archive(self, message: discord.Message):
        await db.touch_profile(self.profile_dict(message.author))
        await db.log_message({
            "message_id": message.id, "guild_id": message.guild.id, "channel_id": message.channel.id,
            "author_id": message.author.id, "author_name": str(message.author),
            "content": message.content, "content_hash": text_hash(message.content),
            "reply_to_id": message.reference.message_id if message.reference else None,
            "created_at_utc": message.created_at.astimezone(UTC).isoformat(),
        })
        shas, items = set(), []
        for att in message.attachments:
            sha, data = None, None
            if att.size <= MAX_READ_BYTES:
                try:
                    data = await att.read()           # memory only
                    sha = hashlib.sha256(data).hexdigest()
                    shas.add(sha)
                except discord.HTTPException:
                    data = None
            await db.add_attachment({
                "message_id": message.id, "guild_id": message.guild.id, "channel_id": message.channel.id,
                "author_id": message.author.id, "filename": att.filename, "url": att.url,
                "mirror_url": None, "sha256": sha, "size": att.size, "content_type": att.content_type,
            })
            items.append((att, data))
        return shas, items

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
        s = await db.get_log_settings(payload.guild_id)
        if s and not s[1]:
            return
        ch = await self.log_channel(payload.guild_id, "messages")
        if not ch:
            return

        await asyncio.sleep(1.5)                      # let the audit-log entry arrive
        deleter = None
        if row:
            e = self.find_recent("message_delete", target=row["author_id"], channel=payload.channel_id, max_age=30)
            deleter = e["actor"] if e else None

        emb = discord.Embed(title="🗑️ Message deleted", color=discord.Color.red(), timestamp=now_utc())
        emb.add_field(name="Channel", value=f"<#{payload.channel_id}>")
        if row:
            emb.add_field(name="Author", value=f"<@{row['author_id']}> (`{row['author_id']}`)")
            emb.add_field(name="Deleted by", value=f"<@{deleter}>" if deleter else "author / a bot (no audit entry)")
            emb.description = short(row["content"], 3500) or "*no text*"
            emb.set_footer(text=f"Message ID {mid} • sent {row['created_at_utc'][:19]} UTC")
            shown = False
            for a in await db.get_attachments(mid):
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
            await ch.send(embed=emb)
        except discord.HTTPException:
            pass

    @commands.Cog.listener()
    async def on_raw_bulk_message_delete(self, payload: discord.RawBulkMessageDeleteEvent):
        ids = list(payload.message_ids)
        await db.mark_deleted(ids)
        if not payload.guild_id or payload.channel_id in self.purging:
            return
        s = await db.get_log_settings(payload.guild_id)
        if s and not s[3]:
            return
        ch = await self.log_channel(payload.guild_id, "messages")
        if not ch:
            return
        rows = await db.get_messages(ids[:10])
        text = "\n".join(f"{r['author_name']}: {short(r['content'], 80)}" for r in rows) or "Not archived."
        await ch.send(f"🧹 Bulk delete in <#{payload.channel_id}> - {len(ids)} messages\n```{text[:1500]}```")

    @commands.Cog.listener()
    async def on_raw_message_edit(self, payload: discord.RawMessageUpdateEvent):
        data = payload.data
        if "content" not in data or (data.get("author") or {}).get("bot"):
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
        await ch.send(embed=emb)

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
        invite = await self.detect_invite(guild)
        joined = member.joined_at or now_utc()
        await db.record_member_join(guild.id, member.id, member.nick, joined.isoformat(),
                                    invite.code if invite else None,
                                    invite.inviter.id if invite and invite.inviter else None)
        await db.upsert_profile(self.profile_dict(member))
        await self.mirror_avatar(member, guild.id)

        if self.flag_applies(member.id, guild.id):
            f = self.flagged[member.id]
            await self.apply_timeout(guild, member.id, self.flag_expiry(f), "Flagged compromised account")
            await self.send_log(guild.id, "security",
                                content=f"🚨 Flagged compromised account {member.mention} (`{member.id}`) just joined - timed out on arrival.")

        lines = ["**Member joined**",
                 f"{member.mention} {ordinal(guild.member_count)} to join",
                 f"created {human_age(member.created_at, now_utc())}",
                 f"ID: {member.id} • {joined.strftime('%d/%m/%Y %H:%M')}"]
        if invite:
            who = invite.inviter.mention if invite.inviter else "unknown"
            lines.append(f"Invite: `{invite.code}` by {who} (uses: {invite.uses})")
        await self.send_log(guild.id, "members", content="\n".join(lines))

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member):
        await db.mark_member_left(member.guild.id, member.id)
        await self.send_log(member.guild.id, "members",
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
        await db.upsert_profile(self.profile_dict(after))

        mirror_url = None
        for g in self.bot.guilds:
            if not g.get_member(after.id):
                continue
            if new_key and mirror_url is None:
                mirror_url = await self.mirror_avatar(after, g.id)
        for kind, _, old, new in changes:
            await db.add_history(after.id, None, kind, old, new, mirror_url if kind == "avatar" else None)

        for g in self.bot.guilds:
            if not g.get_member(after.id):
                continue
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
            await self.send_log(g.id, "members", embed=emb)

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        g = after.guild
        if before.nick != after.nick:
            await db.set_member_nick(g.id, after.id, after.nick)
            await db.add_history(after.id, g.id, "nickname", before.nick, after.nick)
            await asyncio.sleep(1.5)
            e = self.find_recent("member_update", target=after.id, key="nick", max_age=15)
            by = f"<@{e['actor']}>" if e and e["actor"] else "themselves"
            emb = discord.Embed(title="🏷️ Nickname changed", color=discord.Color.blurple(), timestamp=now_utc(),
                                description=f"{after.mention} (`{after.id}`)\n`{before.nick}` → `{after.nick}`")
            emb.add_field(name="Changed by", value=by)
            await self.send_log(g.id, "members", embed=emb)
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
            await self.send_log(g.id, "roles", embed=emb)

    # ------------------------------------------------------------ voice
    @commands.Cog.listener()
    async def on_voice_state_update(self, member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
        g = member.guild
        b, a = before.channel, after.channel
        if b != a:
            if b and a:
                await asyncio.sleep(1.5)
                e = self.consume("member_move", channel=a.id)
                emb = discord.Embed(title="🎤 Voice: moved", color=discord.Color.teal(), timestamp=now_utc(),
                                    description=f"{member.mention} (`{member.id}`)\n{b.mention} → {a.mention}")
                emb.add_field(name="Moved by", value=f"<@{e['actor']}>" if e else "themselves")
            elif a:
                emb = discord.Embed(title="🎤 Voice: joined", color=discord.Color.green(), timestamp=now_utc(),
                                    description=f"{member.mention} (`{member.id}`) → {a.mention}")
            else:
                await asyncio.sleep(1.5)
                e = self.consume("member_disconnect")
                emb = discord.Embed(title="🎤 Voice: left", color=discord.Color.dark_grey(), timestamp=now_utc(),
                                    description=f"{member.mention} (`{member.id}`) ← {b.mention}")
                emb.add_field(name="Disconnected by", value=f"<@{e['actor']}>" if e else "themselves / connection lost")
            await self.send_log(g.id, "voice", embed=emb)
            return
        if a is None:
            return
        notes = []
        if before.self_stream != after.self_stream:
            notes.append("started streaming 🔴" if after.self_stream else "stopped streaming")
        if before.self_video != after.self_video:
            notes.append("camera on 📷" if after.self_video else "camera off")
        if notes:
            await self.send_log(g.id, "voice", embed=discord.Embed(
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
        rec = {"ts": time.monotonic(), "action": act, "actor": entry.user_id, "target": target_id_of(entry),
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
        owner = await self.is_owner(ctx.author)
        if not owner and not ctx.author.guild_permissions.manage_messages:
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
            if not owner and not u_p.manage_messages:
                skipped.append(f"{ch.mention} (you lack Manage Messages)")
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

        def check(m: discord.Message) -> bool:
            return m.id != status.id and (user_ids is None or m.author.id in user_ids)

        total, per_channel = 0, []
        for ch in usable:
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
    def flag_applies(self, uid: int, gid: int):
        f = self.flagged.get(uid)
        if not f or gid in self.exempt.get(uid, ()):
            return None
        if gid != f["source_guild_id"] and gid in self.protect_off:
            return None
        return f

    @staticmethod
    def flag_expiry(flag) -> Optional[datetime]:
        return datetime.fromisoformat(flag["expires_at_utc"]) if flag["expires_at_utc"] else None

    async def apply_timeout(self, guild: discord.Guild, uid: int, expires: Optional[datetime], reason: str) -> str:
        member = guild.get_member(uid)
        if not member:
            return "not a member"
        me = guild.me
        if not me.guild_permissions.moderate_members:
            return "bot lacks Moderate Members"
        if member.guild_permissions.administrator or member.id == guild.owner_id or member.top_role >= me.top_role:
            return "can't time out (admin / role hierarchy)"
        cap = now_utc() + MAX_TIMEOUT
        until = min(expires, cap) if expires else cap
        try:
            await member.timeout(until, reason=f"Compromised-account protection: {reason}"[:500])
            return "timed out"
        except discord.HTTPException as e:
            return f"failed ({e.status})"

    @commands.command(name="compromised", aliases=["hacked"])
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True, moderate_members=True)
    async def compromised(self, ctx, user: Optional[discord.User] = None, duration: str = "24h",
                          *, reason: str = "Account compromised"):
        """Reply to a bad message with `!compromised [24h|7d|perm] [reason]`, or `!compromised @user 7d spam`."""
        target_msg = None
        ref = ctx.message.reference
        if ref and ref.message_id:
            try:
                target_msg = await ctx.channel.fetch_message(ref.message_id)
            except discord.HTTPException:
                pass
        if user is None and target_msg:
            user = target_msg.author
        if user is None:
            return await ctx.send("Reply to the compromised account's message with `!compromised`, "
                                  "or use `!compromised @user [24h|7d|perm] [reason]`.")
        owner = await self.is_owner(ctx.author)
        if user.bot or user.id in (ctx.author.id, self.bot.user.id):
            return await ctx.send("~_~ Can't flag that account.")
        if not owner and ctx.guild.get_member(user.id) is None:
            return await ctx.send("~_~ That user must be a member of this server to be flagged from here.")

        if duration.lower() in ("perm", "permanent", "manual"):
            expires = None
        else:
            span = parse_span(duration)
            if span in (None, "all"):
                return await ctx.send("~_~ Duration looks like `24h`, `7d`, `2w` or `perm` (until you clear it).")
            expires = now_utc() + span

        await db.flag_user(user.id, ctx.author.id, ctx.guild.id, reason[:300], expires.isoformat() if expires else None)

        since = (now_utc() - timedelta(hours=1)).isoformat()
        rows = await db.recent_messages_by_author(user.id, since, 200)
        seen, made = set(), 0
        for r in rows:
            shas = {a["sha256"] for a in await db.get_attachments(r["message_id"]) if a["sha256"]}
            doms = domains_of(r["content"])
            key = (r["content_hash"], frozenset(doms), frozenset(shas))
            if key in seen or not (r["content_hash"] or doms or shas) or made >= 10:
                continue
            seen.add(key)
            made += 1
            await db.add_fingerprint(user.id, r["content_hash"], ",".join(doms), ",".join(shas),
                                     norm_text(r["content"])[:500])
        if target_msg and not any(r["message_id"] == target_msg.id for r in rows):
            h, doms = text_hash(target_msg.content), domains_of(target_msg.content)
            if h or doms:
                await db.add_fingerprint(user.id, h, ",".join(doms), "", norm_text(target_msg.content)[:500])
        await self.refresh_cache()

        deleted = 0
        for r in rows:
            ch = self.bot.get_channel(r["channel_id"])
            if not ch or not getattr(ch, "guild", None) or not self.flag_applies(user.id, ch.guild.id):
                continue
            self.silent_ids.add(r["message_id"])
            try:
                await ch.get_partial_message(r["message_id"]).delete()
                deleted += 1
            except discord.HTTPException:
                self.silent_ids.discard(r["message_id"])
        if target_msg:
            self.silent_ids.add(target_msg.id)
            try:
                await target_msg.delete()
            except discord.HTTPException:
                self.silent_ids.discard(target_msg.id)
        await db.mark_deleted([r["message_id"] for r in rows])

        applied, details = 0, []
        for g in self.bot.guilds:
            if not g.get_member(user.id) or not self.flag_applies(user.id, g.id):
                continue
            res = await self.apply_timeout(g, user.id, expires, reason)
            applied += res == "timed out"
            details.append((g, res))
            emb = discord.Embed(title="🚨 Compromised account flagged", color=discord.Color.dark_red(), timestamp=now_utc(),
                                description=f"{user.mention} (`{user.id}`)\n**Reason:** {reason}")
            emb.add_field(name="Flagged by", value=f"{ctx.author} in **{ctx.guild.name}**")
            emb.add_field(name="Until", value=f"<t:{int(expires.timestamp())}:R>" if expires else "cleared manually")
            emb.add_field(name="Result here", value=res)
            await self.send_log(g.id, "security", embed=emb)

        out = discord.Embed(title="🚨 Account flagged network-wide", color=discord.Color.dark_red(),
                            description=f"{user.mention} (`{user.id}`)")
        out.add_field(name="Timed out", value=f"{applied} server(s)")
        out.add_field(name="Messages removed", value=str(deleted))
        out.add_field(name="Fingerprints", value=f"{made} scam pattern(s) now blocked")
        out.add_field(name="Ends", value=f"<t:{int(expires.timestamp())}:R>" if expires else "when you run `!uncompromised`")
        if owner:
            out.add_field(name="Per server", value="\n".join(f"{g.name}: {r}" for g, r in details)[:1000] or "-", inline=False)
        else:
            fails = sum(1 for _, r in details if r != "timed out")
            if fails:
                out.set_footer(text=f"{fails} server(s) couldn't be timed out (permissions/hierarchy) - messages are still auto-deleted there.")
        await ctx.send(embed=out)

    @commands.command(name="uncompromised", aliases=["clearflag"])
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True, moderate_members=True)
    async def uncompromised(self, ctx, user: discord.User):
        """Source server (or bot owner): clears the flag everywhere. Other servers: clears it for themselves only."""
        flag = await db.get_flag(user.id)
        if not flag:
            return await ctx.send("That account isn't flagged.")
        owner = await self.is_owner(ctx.author)
        if owner or flag["source_guild_id"] == ctx.guild.id:
            await db.clear_flag(user.id)
            await self.refresh_cache()
            lifted = 0
            for g in self.bot.guilds:
                m = g.get_member(user.id)
                if m and m.is_timed_out() and g.me.guild_permissions.moderate_members:
                    try:
                        await m.timeout(None, reason="Compromised flag cleared")
                        lifted += 1
                    except discord.HTTPException:
                        pass
            return await ctx.send(f"✅ {user.mention} cleared everywhere. Timeouts lifted in {lifted} server(s).")
        await db.add_exempt(ctx.guild.id, user.id)
        await self.refresh_cache()
        m = ctx.guild.get_member(user.id)
        if m and m.is_timed_out():
            try:
                await m.timeout(None, reason="Compromised flag cleared locally")
            except discord.HTTPException:
                pass
        await ctx.send(f"✅ {user.mention} is exempt in **this** server. The flag stays active in the server that raised it.")

    @commands.command(name="flagged")
    @commands.guild_only()
    @commands.has_permissions(moderate_members=True)
    async def flagged_list(self, ctx):
        flags = await db.get_active_flags()
        if not flags:
            return await ctx.send("No active compromised-account flags.")
        owner = await self.is_owner(ctx.author)
        lines = []
        for f in flags[:25]:
            src = self.bot.get_guild(f["source_guild_id"])
            srcname = src.name if src and (owner or src.id == ctx.guild.id) else "another server"
            end = f"<t:{int(datetime.fromisoformat(f['expires_at_utc']).timestamp())}:R>" if f["expires_at_utc"] else "manual"
            lines.append(f"<@{f['user_id']}> (`{f['user_id']}`) - {srcname} - ends {end} - {f['reason'][:60]}")
        await ctx.send(embed=discord.Embed(title="🚨 Active flags", description="\n".join(lines), color=discord.Color.dark_red()))

    async def enforce(self, message: discord.Message, shas: set):
        uid, gid = message.author.id, message.guild.id
        reason = None
        if self.flag_applies(uid, gid):
            reason = "flagged compromised account"
        elif self.fp_cache and gid not in self.protect_off and not message.author.guild_permissions.manage_messages:
            reason = self.match_fingerprint(message, shas)
        if not reason:
            return
        self.silent_ids.add(message.id)
        try:
            await message.delete()
        except discord.HTTPException:
            self.silent_ids.discard(message.id)
            return
        if reason == "flagged compromised account" and not message.author.is_timed_out():
            f = self.flagged[uid]
            await self.apply_timeout(message.guild, uid, self.flag_expiry(f), f["reason"])
        await self.send_log(gid, "security",
                            content=f"🛡️ Deleted a message from {message.author.mention} in {message.channel.mention} - {reason}.")

    def match_fingerprint(self, message: discord.Message, shas: set) -> Optional[str]:
        h, norm, doms = text_hash(message.content), norm_text(message.content)[:500], domains_of(message.content)
        for fp in self.fp_cache:
            if fp["user_id"] == message.author.id:
                continue
            if h and h == fp["hash"]:
                return "matches a flagged scam message"
            if doms & fp["domains"]:
                return "contains a flagged scam link"
            if shas & fp["shas"]:
                return "contains a flagged scam image"
            if len(norm) >= 25 and len(fp["norm"]) >= 25:
                sm = SequenceMatcher(None, norm, fp["norm"])
                if sm.quick_ratio() >= 0.9 and sm.ratio() >= 0.9:
                    return "near-duplicate of a flagged scam message"
        return None

    @tasks.loop(seconds=60)
    async def enforce_loop(self):
        try:
            for uid in await db.expire_flags():
                for g in self.bot.guilds:
                    m = g.get_member(uid)
                    if m and m.is_timed_out() and g.me.guild_permissions.moderate_members:
                        try:
                            await m.timeout(None, reason="Compromised flag expired")
                        except discord.HTTPException:
                            pass
            await self.refresh_cache()
            now = now_utc()
            cap = now + MAX_TIMEOUT
            for uid, f in self.flagged.items():
                exp = self.flag_expiry(f)
                for g in self.bot.guilds:
                    m = g.get_member(uid)
                    if not m or not self.flag_applies(uid, g.id):
                        continue
                    tu = m.timed_out_until
                    if exp and exp <= cap:
                        need = tu is None or tu < exp - timedelta(seconds=90)
                    else:
                        need = tu is None or tu < now + timedelta(days=7)
                    if need:
                        await self.apply_timeout(g, uid, exp, f["reason"])
        except Exception as e:
            print(f"[guardian] enforce loop error: {e}")

    @enforce_loop.before_loop
    async def _before_enforce(self):
        await self.bot.wait_until_ready()

    @tasks.loop(hours=6)
    async def retention_loop(self):
        if RETENTION_DAYS > 0:
            try:
                await db.prune_messages((now_utc() - timedelta(days=RETENTION_DAYS)).isoformat())
            except Exception as e:
                print(f"[guardian] retention error: {e}")

    # ------------------------------------------------------------ userinfo / alt check
    @commands.command(name="userinfo", aliases=["whois", "trace"])
    @commands.guild_only()
    @commands.has_permissions(moderate_members=True)
    async def userinfo(self, ctx, user: discord.User):
        owner = await self.is_owner(ctx.author)
        await db.upsert_profile(self.profile_dict(user))
        snap = await self.mirror_avatar(user, ctx.guild.id)
        prof = await db.get_profile(user.id)

        emb = discord.Embed(title=f"🔎 {user}", color=discord.Color.blurple(), timestamp=now_utc())
        emb.set_thumbnail(url=user.display_avatar.url)
        emb.add_field(name="ID", value=f"`{user.id}`")
        emb.add_field(name="Account created", value=f"<t:{int(user.created_at.timestamp())}:F>")
        emb.add_field(name="First seen by bot", value=prof["first_seen_utc"][:10] if prof else "-")
        emb.add_field(name="Avatar", value=f"[snapshot]({snap})" if snap else "default")
        emb.add_field(name="Messages archived here", value=str(await db.count_messages(user.id, ctx.guild.id)))
        flag = await db.get_flag(user.id)
        if flag:
            emb.add_field(name="🚨 Flagged", value=flag["reason"][:100])

        hist = await db.get_history(user.id, None if owner else ctx.guild.id, 12)
        if hist:
            lines = []
            for h in hist:
                extra = f" [view]({h['mirror_url']})" if h.get("mirror_url") else ""
                lines.append(f"`{h['changed_at_utc'][:10]}` {h['kind']}: `{h['old_value']}` → `{h['new_value']}`{extra}")
            emb.add_field(name="Name / nickname / avatar history", value="\n".join(lines)[:1000], inline=False)

        mem_lines = []
        for m in await db.get_memberships(user.id):
            g = self.bot.get_guild(m["guild_id"])
            if not g or not (owner or g.get_member(ctx.author.id)):
                continue
            left = " (left)" if m["left_at_utc"] else ""
            inv = f" via `{m['invite_code']}`" if m["invite_code"] else ""
            mem_lines.append(f"**{g.name}**{left} nick: `{m['nickname']}` joined {str(m['joined_at_utc'])[:10]}{inv}")
        if mem_lines:
            emb.add_field(name="Servers" if owner else "Servers (that you're also in)",
                          value="\n".join(mem_lines)[:1000], inline=False)

        events = await db.get_audit_events(user.id, ctx.guild.id, 6)
        if events:
            lines = []
            for ev in events:
                role = "by" if ev["actor_id"] == user.id else "on"
                other = ev["target_id"] if role == "by" else ev["actor_id"]
                lines.append(f"`{ev['created_at_utc'][:10]}` {ev['action'].replace('_', ' ')} ({role} them" +
                             (f", other: <@{other}>" if other else "") + ")")
            emb.add_field(name="Recent staff actions here", value="\n".join(lines)[:1000], inline=False)

        signals = await db.alt_signals(user.id)
        scored = sorted(((sum(w for _, w in r), uid, r) for uid, r in signals.items()), reverse=True)
        alt_lines = []
        for score, uid, reasons in scored:
            if score < 25 or len(alt_lines) >= 6:
                break
            label = "strong" if score >= 60 else "likely" if score >= 35 else "weak"
            p = await db.get_profile(uid)
            alt_lines.append(f"<@{uid}> (`{uid}`, {p['username'] if p else '?'}) - **{label}** ({score}): " +
                             "; ".join(r for r, _ in reasons))
        emb.add_field(name="Possible alternate accounts (heuristic, not proof)",
                      value="\n".join(alt_lines)[:1000] if alt_lines else "Nothing notable.", inline=False)
        await ctx.send(embed=emb)


async def setup(bot: commands.Bot):
    await bot.add_cog(Guardian(bot))
