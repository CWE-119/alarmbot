"""
Alarm Bot
  * alarms + timezones                       (this file)
  * logging / moderation / protection        (guardian.py, loaded below)
"""
import os
import re
from datetime import datetime, timedelta

import discord
import pytz
from dateutil import parser as dateparser
from discord.ext import commands, tasks
from dotenv import load_dotenv

from database import (
    add_alarm, delete_alarm, get_due_alarms, get_user_alarms, get_user_timezone, init_db,
    set_alarm_paused, set_user_timezone, snooze_alarm, update_alarm, update_alarm_time,
)

load_dotenv()

# default intents already include guilds, messages, voice_states, invites and moderation (audit log);
# the two below are privileged - enable them in the Developer Portal as well.
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


@bot.event
async def setup_hook():
    await init_db()                       # idempotent; data lives in DATA_DIR and survives restarts
    await bot.load_extension("guardian")
    check_alarms.start()


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id}) - {len(bot.guilds)} server(s)")
    await bot.change_presence(status=discord.Status.online)


# ============================================================ help
# (title, required permissions, [(command, description), ...])  - sections are hidden from people who can't use them
HELP_SECTIONS = [
    ("⏰ Alarms", (), [
        ("!settimezone <Area/City>", "e.g. `Asia/Dhaka`, `America/New_York`"),
        ("!gettimezone", "show your timezone"),
        ("!setalarm <time> [daily|weekly] [| message]", "e.g. `!setalarm tomorrow 9am daily | Wake up` · `!setalarm in 2h | Tea` · `!setalarm 15:30`"),
        ("!listalarms", "your alarms"),
        ("!editalarm <id> <time> [daily|weekly] [| message]", "change time / repeat / message"),
        ("!snooze <id> <10m|2h|1d>", "push an alarm back"),
        ("!pausealarm <id>  ·  !resumealarm <id>", "pause / resume"),
        ("!deletealarm <id>", "remove an alarm"),
    ]),
    ("🧹 Delete messages  (Manage Messages)", ("manage_messages",), [
        ("!alarmbot -d -u @user -t 1H -c #a #b", "`-u` users (several, or `all`) · `-t` time `30m` `1H` `2d` `1w` `6mo` `1y` `1d12h` or `all` · "
                                                 "`-c` channels (several, a category, `all`; omit = this channel). Asks to confirm when it's broad."),
    ]),
    ("🚨 Compromised accounts  (Manage Messages + Moderate Members)", ("manage_messages", "moderate_members"), [
        ("!compromised [@user] [24h|7d|perm] [reason]", "or just **reply** to the bad message with `!compromised`. Deletes their last hour of messages, "
                                                        "times them out and blocks the same scam text/links/images in every server the bot is in."),
        ("!uncompromised @user", "clear it (the server that flagged clears it everywhere; others exempt only themselves)"),
        ("!flagged", "list active flags"),
    ]),
    ("🔎 Investigation  (Moderate Members)", ("moderate_members",), [
        ("!userinfo @user", "name / nickname / avatar history, servers, join invite, staff actions, possible alt accounts (aliases: `!whois`, `!trace`)"),
    ]),
    ("📜 Logging & server setup  (Administrator)", ("administrator",), [
        ("!setuplogs #channel", "one-time setup: default log channel + every log type on (alias `!setlogchannel`)"),
        ("!setlog <category> <#channel|off|default>", "send a category to its own channel. Categories: `messages` `media` `members` `voice` `roles` `moderation` `server` `security`"),
        ("!logstatus", "show where everything goes + which bot permissions are missing"),
        ("!toggledeletelog · !toggleeditlog · !togglebulkdeletelog", "switch those message logs on/off"),
        ("!mediamirror on|off", "copy attachments into the `media` log channel as they're sent"),
        ("!protect on|off", "accept (or ignore) compromised-account flags raised by other servers"),
    ]),
    ("👑 Bot owner", ("owner",), [
        ("!forgetuser <user id>", "erase everything stored about a user"),
    ]),
]


async def visible_sections(ctx, show_all: bool):
    perms = ctx.author.guild_permissions if ctx.guild else discord.Permissions.none()
    is_owner = await bot.is_owner(ctx.author)
    for title, needed, rows in HELP_SECTIONS:
        if show_all or is_owner or all((n == "owner" and is_owner) or getattr(perms, n, False) for n in needed):
            yield title, rows


@bot.command(name="help", aliases=["alarmhelp"])
async def help_command(ctx, what: str = ""):
    """Shows only the commands you are allowed to use. `!help all` shows everything."""
    embed = discord.Embed(title="Alarm Bot - commands",
                          description="Times use your timezone (default UTC).  `[ ]` optional · `< >` required",
                          color=discord.Color.blue())
    shown = 0
    async for title, rows in visible_sections(ctx, what.lower() == "all"):
        embed.add_field(name=title, value="\n".join(f"`{cmd}`\n└ {desc}" for cmd, desc in rows)[:1024], inline=False)
        shown += 1
    if shown < len(HELP_SECTIONS):
        embed.set_footer(text=f"{len(HELP_SECTIONS) - shown} more section(s) need extra permissions - `!help all` lists them")
    await ctx.send(embed=embed)


# ============================================================ time parsing
REPEATS = {"daily", "weekly"}


def parse_duration(s: str):
    """'10m' '2h' '1d' (also '2 hours', '30 mins') -> timedelta | None"""
    m = re.fullmatch(r"\s*(\d+)\s*([a-z]+)\s*", s.lower())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    if unit in ("m", "min", "mins", "minute", "minutes"):
        return timedelta(minutes=n)
    if unit in ("h", "hr", "hrs", "hour", "hours"):
        return timedelta(hours=n)
    if unit in ("d", "day", "days"):
        return timedelta(days=n)
    return None


def parse_when(text: str, tz, now: datetime):
    """'9am' · '15:30' · 'tomorrow 9am' · 'today 18:00' · 'in 2h' · 'Jan 5 18:00' -> aware datetime in tz, or None."""
    t = text.strip().lower()
    if not t:
        return None

    m = re.fullmatch(r"in\s+(\d+\s*[a-z]+)", t)                 # relative: "in 2h"
    if m:
        delta = parse_duration(m.group(1))
        return (now.astimezone(pytz.UTC) + delta).astimezone(tz) if delta else None

    base = now.replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)   # naive midnight; localized after parsing (DST-safe)
    words, explicit_day = t.split(), False
    if words[0] in ("today", "tomorrow"):
        explicit_day = True
        if words[0] == "tomorrow":
            base += timedelta(days=1)
        words = words[1:]
        if not words:
            return None
    try:
        parsed = dateparser.parse(" ".join(words), fuzzy=False, default=base)
    except (ValueError, OverflowError):
        return None

    when = tz.localize(parsed)
    if when <= now and not explicit_day:                        # bare "9am" that already passed -> tomorrow
        when = tz.localize(parsed + timedelta(days=1))
    return when if when > now else None


def parse_alarm_args(raw: str, tz, now: datetime):
    """
    '<time> [daily|weekly] [| message]'  or  '<time> [daily|weekly] message words'
    -> (when, repeat, message | None). Raises ValueError with a user-facing reason.
    """
    has_pipe = "|" in raw
    left, message = (raw.split("|", 1) if has_pipe else (raw, ""))
    message = message.strip() or None

    tokens, repeat = left.split(), None
    for i, tok in enumerate(tokens):                            # first daily/weekly word = repeat
        if tok.lower() in REPEATS:
            repeat = tok.lower()
            del tokens[i]
            break

    when = None
    if has_pipe:
        when = parse_when(" ".join(tokens), tz, now)
    else:                                                       # longest leading phrase that is a time; rest = message
        for k in range(min(len(tokens), 8), 0, -1):
            when = parse_when(" ".join(tokens[:k]), tz, now)
            if when:
                message = " ".join(tokens[k:]) or None
                break
    if when is None:
        raise ValueError("Couldn't read that time (or it's already past). Try `tomorrow 9am`, `15:30`, `in 2h`, "
                         "and use `|` before the message: `!setalarm 9am daily | Wake up`")
    return when, repeat, message


def next_recurring_utc(alarm_time_utc_iso: str, tz_name: str, repeat: str) -> datetime:
    """Next occurrence of a daily/weekly alarm; stays on the same local clock time across DST changes."""
    tz = pytz.timezone(tz_name)
    old = datetime.fromisoformat(alarm_time_utc_iso)
    if old.tzinfo is None:
        old = pytz.UTC.localize(old)
    step = timedelta(weeks=1) if repeat == "weekly" else timedelta(days=1)
    local = old.astimezone(tz).replace(tzinfo=None) + step
    return tz.localize(local).astimezone(pytz.UTC)


# ============================================================ timezone commands
@bot.command(name="settimezone")
async def set_timezone(ctx, timezone: str):
    try:
        pytz.timezone(timezone)
    except pytz.UnknownTimeZoneError:
        return await ctx.send('~_~ Invalid timezone. Use format like "Continent/City"')
    await set_user_timezone(ctx.author.id, timezone)
    await ctx.send(f"(⊙_⊙)？ Timezone set to {timezone}")


@bot.command(name="gettimezone")
async def get_timezone(ctx):
    await ctx.send(f"(￣┰￣*) Your timezone: {await get_user_timezone(ctx.author.id)}")


# ============================================================ alarm commands
async def owned_alarm(ctx, alarm_id: int):
    """The alarm if it belongs to the caller; otherwise replies and returns None."""
    alarm = next((a for a in await get_user_alarms(ctx.author.id) if a["id"] == alarm_id), None)
    if alarm is None:
        await ctx.send("~_~ Alarm not found")
    return alarm


def describe(when: datetime, tz_name: str, repeat) -> str:
    return f"{when.strftime('%Y-%m-%d %H:%M')} ({tz_name})" + (f" · repeats {repeat}" if repeat else "")


@bot.command(name="setalarm")
async def set_alarm(ctx, *, raw: str):
    tz_name = await get_user_timezone(ctx.author.id)
    tz = pytz.timezone(tz_name)
    try:
        when, repeat, message = parse_alarm_args(raw, tz, datetime.now(tz))
    except ValueError as e:
        return await ctx.send(f"~_~ {e}")
    message = message or "Alarm!"
    alarm_id = await add_alarm(ctx.author.id, when.astimezone(pytz.UTC), message, ctx.channel.id, tz_name, repeat)
    await ctx.send(f"(＞﹏＜ Alarm set for {describe(when, tz_name, repeat)}\nMessage: {message}\nID: {alarm_id}")


@bot.command(name="listalarms")
async def list_alarms(ctx):
    alarms = await get_user_alarms(ctx.author.id)
    if not alarms:
        return await ctx.send("(￣o￣).zZ  No active alarms")
    tz = pytz.timezone(await get_user_timezone(ctx.author.id))
    rows = []
    for a in alarms:
        local = datetime.fromisoformat(a["time"]).astimezone(tz)
        paused = " [PAUSED]" if a["paused"] else ""
        repeat = f" (Repeats {a['repeat']})" if a["repeat"] else ""
        rows.append(f"**ID {a['id']}**{paused} - {local.strftime('%a %b %d %H:%M')}{repeat}\nMessage: {a['message']}")
    await ctx.send(embed=discord.Embed(title="Your Active Alarms", description="\n\n".join(rows),
                                       color=discord.Color.gold()))


@bot.command(name="editalarm")
async def edit_alarm(ctx, alarm_id: int, *, raw: str):
    alarm = await owned_alarm(ctx, alarm_id)
    if not alarm:
        return
    tz_name = await get_user_timezone(ctx.author.id)
    tz = pytz.timezone(tz_name)
    try:
        when, repeat, message = parse_alarm_args(raw, tz, datetime.now(tz))
    except ValueError as e:
        return await ctx.send(f"~_~ {e}")
    repeat = repeat or alarm["repeat"]                          # keep old repeat/message unless changed
    message = message or alarm["message"]
    await update_alarm(alarm_id, when.astimezone(pytz.UTC), repeat, message)
    await ctx.send(f"✅ Alarm {alarm_id} updated: {describe(when, tz_name, repeat)}")


@bot.command(name="deletealarm")
async def delete_alarm_command(ctx, alarm_id: int):
    if await owned_alarm(ctx, alarm_id):
        await delete_alarm(alarm_id)
        await ctx.send(f"✅ Alarm {alarm_id} deleted")


@bot.command(name="snooze")
async def snooze_command(ctx, alarm_id: int, duration: str):
    if not await owned_alarm(ctx, alarm_id):
        return
    delta = parse_duration(duration)
    if not delta:
        return await ctx.send("~_~ Invalid duration. Use like `10m`, `2h`, `1d`")
    await snooze_alarm(alarm_id, delta)
    await ctx.send("✅ Snoozed")


@bot.command(name="pausealarm")
async def pause_alarm(ctx, alarm_id: int):
    if await owned_alarm(ctx, alarm_id):
        await set_alarm_paused(alarm_id, True)
        await ctx.send(f"⏸️ Alarm {alarm_id} paused")


@bot.command(name="resumealarm")
async def resume_alarm(ctx, alarm_id: int):
    if await owned_alarm(ctx, alarm_id):
        await set_alarm_paused(alarm_id, False)
        await ctx.send(f"▶️ Alarm {alarm_id} resumed")


# ============================================================ alarm checker
async def fail_alarm(alarm: dict):
    """Safest handling when an alarm can't be delivered: pause recurring ones, drop one-time ones."""
    if alarm["repeat"]:
        await set_alarm_paused(alarm["id"], True)
    else:
        await delete_alarm(alarm["id"])


@tasks.loop(seconds=10)
async def check_alarms():
    for alarm in await get_due_alarms():
        try:
            channel = bot.get_channel(alarm["channel_id"]) if alarm["channel_id"] else None
            if channel is None:
                await fail_alarm(alarm)
                continue
            await channel.send(f"🔔 <@{alarm['user_id']}> **ALARM**: {alarm['message']}")
            if alarm["repeat"]:
                await update_alarm_time(alarm["id"], next_recurring_utc(alarm["time"], alarm["timezone"], alarm["repeat"]))
            else:
                await delete_alarm(alarm["id"])
        except Exception as e:
            print(f"Error triggering alarm {alarm.get('id')}: {e}")
            await fail_alarm(alarm)


@check_alarms.before_loop
async def _before_check_alarms():
    await bot.wait_until_ready()


# ============================================================ errors
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingPermissions):
        return await ctx.send("~_~ You don't have permission for that.")
    if isinstance(error, (commands.NotOwner, commands.CheckFailure, commands.NoPrivateMessage)):
        return await ctx.send("~_~ You can't use that here.")
    if isinstance(error, (commands.MissingRequiredArgument, commands.BadArgument)):
        return await ctx.send(f"~_~ Check the command usage with `!help` ({error})")
    await ctx.send("~_~ Something went wrong.")
    raise error


if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("~_~ DISCORD_TOKEN is missing - put it in .env")
    try:
        bot.run(token)
    except discord.LoginFailure:
        raise SystemExit("~_~ Invalid token - check your DISCORD_TOKEN")
