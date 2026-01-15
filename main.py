import discord
from discord.ext import commands, tasks
from datetime import datetime, timedelta
from dateutil import parser
from dateutil.relativedelta import relativedelta
import pytz
import os
from dotenv import load_dotenv

from database import *

load_dotenv()

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
intents.members = True
intents.voice_states = True
intents.guilds = True
intents.invites = True

guild_invites = {}

bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# ---------- Helpers ----------
def ordinal(n: int) -> str:
    if 10 <= (n % 100) <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"

def human_age(from_dt: datetime, to_dt: datetime) -> str:
    # returns "3 years, 10 months and 2 days ago"
    if from_dt > to_dt:
        from_dt, to_dt = to_dt, from_dt
    rd = relativedelta(to_dt, from_dt)

    parts = []
    if rd.years:
        parts.append(f"{rd.years} year{'s' if rd.years != 1 else ''}")
    if rd.months:
        parts.append(f"{rd.months} month{'s' if rd.months != 1 else ''}")
    if rd.days:
        parts.append(f"{rd.days} day{'s' if rd.days != 1 else ''}")

    if not parts:
        return "just now"

    if len(parts) == 1:
        return parts[0] + " ago"
    if len(parts) == 2:
        return parts[0] + " and " + parts[1] + " ago"
    return ", ".join(parts[:-1]) + " and " + parts[-1] + " ago"

def parse_duration(s: str) -> timedelta | None:
    # supports: 10m, 2h, 1d
    s = s.strip().lower()
    if not s:
        return None
    num = ""
    unit = ""
    for ch in s:
        if ch.isdigit():
            num += ch
        else:
            unit += ch
    if not num or not unit:
        return None
    n = int(num)
    if unit in ("m", "min", "mins", "minute", "minutes"):
        return timedelta(minutes=n)
    if unit in ("h", "hr", "hrs", "hour", "hours"):
        return timedelta(hours=n)
    if unit in ("d", "day", "days"):
        return timedelta(days=n)
    return None

def compute_next_recurring_utc(alarm_time_utc_iso: str, user_tz_name: str, repeat: str) -> datetime:
    """
    DST-safe:
    - Convert stored UTC time to user's tz
    - Add 1 day / 1 week in *local tz*
    - Normalize, then convert back to UTC for storage
    """
    tz = pytz.timezone(user_tz_name)
    old_utc = datetime.fromisoformat(alarm_time_utc_iso)
    if old_utc.tzinfo is None:
        old_utc = pytz.UTC.localize(old_utc)

    local = old_utc.astimezone(tz)

    if repeat == "daily":
        local_next = local + timedelta(days=1)
    elif repeat == "weekly":
        local_next = local + timedelta(weeks=1)
    else:
        local_next = local + timedelta(days=1)

    # pytz normalize handles DST transitions
    local_next = tz.normalize(local_next)
    return local_next.astimezone(pytz.UTC)

# ---------- Help ----------
@bot.command(name='alarmhelp')
async def custom_help(ctx):
    help_embed = discord.Embed(
        title="Alarm Bot Commands Help",
        description="Times are handled in your set timezone (default: UTC)",
        color=discord.Color.blue()
    )

    basic_commands = {
        '!alarmhelp': 'Shows this help message',
        '!settimezone <timezone>': 'Example: Asia/Dhaka, America/New_York',
        '!gettimezone': 'Shows your current timezone',
        '!setalarm <time> [daily|weekly] [message...]': 'Example: !setalarm "tomorrow 9am" daily Wake up!',
        '!listalarms': 'Lists your alarms',
        '!deletealarm <id>': 'Deletes an alarm',
        '!editalarm <id> <new time> [daily|weekly] [message...]': 'Edit time/repeat/message',
        '!snooze <id> <10m|2h|1d>': 'Snooze an alarm',
        '!pausealarm <id>': 'Pause an alarm (recurring or one-time)',
        '!resumealarm <id>': 'Resume an alarm'
    }

    admin_commands = {
        '!setlogchannel <channel>': 'Sets server logging channel (admin)',
        '!toggledeletelog': 'Toggle delete logging (admin)',
        '!toggleeditlog': 'Toggle edit logging (admin)',
        '!togglebulkdeletelog': 'Toggle bulk delete logging (admin)'
    }

    help_embed.add_field(name="Basic Commands", value="‎", inline=False)
    for cmd, desc in basic_commands.items():
        help_embed.add_field(name=cmd, value=desc, inline=False)

    help_embed.add_field(name="Admin Commands", value="‎", inline=False)
    for cmd, desc in admin_commands.items():
        help_embed.add_field(name=cmd, value=desc, inline=False)

    await ctx.send(embed=help_embed)

# ---------- Timezone ----------
@bot.command(name='settimezone')
async def set_timezone(ctx, timezone: str):
    try:
        pytz.timezone(timezone)
        await set_user_timezone(ctx.author.id, timezone)
        await ctx.send(f'(⊙_⊙)？ Timezone set to {timezone}')
    except pytz.UnknownTimeZoneError:
        await ctx.send('~_~ Invalid timezone. Use format like "Continent/City"')

@bot.command(name='gettimezone')
async def get_timezone(ctx):
    timezone = await get_user_timezone(ctx.author.id)
    await ctx.send(f'(￣┰￣*) Your timezone: {timezone}')

# ---------- Alarm Commands ----------
@bot.command(name='setalarm')
async def set_alarm(ctx, *, raw: str):
    """
    Usage:
      !setalarm <time> [daily|weekly] [message...]
    Examples:
      !setalarm tomorrow 9am daily Wake up
      !setalarm 15:30 Weekly Standup
    """
    try:
        user_id = ctx.author.id
        timezone = await get_user_timezone(user_id)
        tz = pytz.timezone(timezone)
        now = datetime.now(tz)

        tokens = raw.strip().split()
        repeat = None
        repeat_candidates = {"daily", "weekly"}

        # Try detect repeat token anywhere; best effort:
        # If last tokens include daily/weekly, treat it as repeat.
        # We'll prefer the first occurrence.
        for i, t in enumerate(tokens):
            tl = t.lower()
            if tl in repeat_candidates:
                repeat = tl
                tokens.pop(i)
                break

        time_str = " ".join(tokens).strip()
        message = "Alarm!"

        # If user wrote: !setalarm <time> <message...>
        # We parse time using dateutil fuzzy; it can handle extra words,
        # but we want message support. So we do this:
        # - Parse using full string, but we also allow a delimiter: |
        if "|" in raw:
            left, right = raw.split("|", 1)
            left = left.strip()
            right = right.strip()
            # re-detect repeat on left side
            ltoks = left.split()
            repeat = None
            for i, t in enumerate(list(ltoks)):
                tl = t.lower()
                if tl in repeat_candidates:
                    repeat = tl
                    ltoks.pop(i)
                    break
            time_str = " ".join(ltoks).strip()
            message = right if right else "Alarm!"
        else:
            # If there are many words, user probably included a message.
            # We'll parse time from the front, and treat the remainder as message.
            # Heuristic: progressively extend time phrase until parse succeeds with confidence.
            # We'll do a simple split: try first 1..N tokens as time, remaining as message.
            best_time = None
            best_k = None
            for k in range(1, min(len(tokens), 8) + 1):
                candidate = " ".join(tokens[:k])
                try:
                    parsed = parser.parse(candidate, fuzzy=False, default=now)
                    best_time = parsed
                    best_k = k
                except Exception:
                    continue
            if best_time is None:
                # fallback: let dateutil fuzzy parse entire string as time
                best_time = parser.parse(time_str, fuzzy=True, default=now)
                best_k = len(tokens)

            parsed_time = best_time
            msg_tokens = tokens[best_k:]
            if msg_tokens:
                message = " ".join(msg_tokens).strip()

        parsed_time = parser.parse(time_str, fuzzy=True, default=now)

        if parsed_time.tzinfo is None:
            parsed_time = tz.localize(parsed_time)

        if parsed_time <= now:
            # push to next day if needed
            parsed_time = parsed_time + timedelta(days=1)
            parsed_time = tz.normalize(parsed_time)

        alarm_id = await add_alarm(
            user_id=user_id,
            time_utc=parsed_time.astimezone(pytz.UTC),
            message=message,
            channel_id=ctx.channel.id,
            timezone=timezone,
            repeat=repeat
        )

        await ctx.send(
            f"(＞﹏＜ Alarm set for {parsed_time.strftime('%Y-%m-%d %H:%M')} ({timezone})\n"
            f"Message: {message}\n"
            f"ID: {alarm_id}"
            + (f"\nRepeat: {repeat}" if repeat else "")
        )

    except (ValueError, OverflowError):
        await ctx.send("~_~ Invalid time format. Try: `!setalarm tomorrow 9am daily | Wake up!`")

@bot.command(name='listalarms')
async def list_alarms(ctx):
    alarms = await get_user_alarms(ctx.author.id)
    if not alarms:
        await ctx.send("(￣o￣).zZ  No active alarms")
        return

    timezone = pytz.timezone(await get_user_timezone(ctx.author.id))
    alarm_list = []

    for alarm in alarms:
        local_time = datetime.fromisoformat(alarm['time'])
        if local_time.tzinfo is None:
            local_time = pytz.UTC.localize(local_time)
        local_time = local_time.astimezone(timezone)

        repeat_str = f" (Repeats {alarm['repeat']})" if alarm['repeat'] else ""
        paused_str = " [PAUSED]" if alarm.get("paused") else ""
        alarm_list.append(
            f"**ID {alarm['id']}**{paused_str} - {local_time.strftime('%a %b %d %H:%M')}{repeat_str}\n"
            f"Message: {alarm['message']}"
        )

    embed = discord.Embed(
        title="Your Active Alarms",
        description="\n\n".join(alarm_list),
        color=discord.Color.gold()
    )
    await ctx.send(embed=embed)

@bot.command(name='deletealarm')
async def delete_alarm_command(ctx, alarm_id: int):
    user_alarms = await get_user_alarms(ctx.author.id)
    if any(a['id'] == alarm_id for a in user_alarms):
        await delete_alarm(alarm_id)
        await ctx.send(f"✅ Alarm {alarm_id} deleted")
    else:
        await ctx.send("~_~ Alarm not found")

@bot.command(name='editalarm')
async def edit_alarm_command(ctx, alarm_id: int, *, raw: str):
    """
    Usage:
      !editalarm <id> <new time> [daily|weekly] [message...]
    Tip: Use delimiter:
      !editalarm 3 tomorrow 9am daily | Wake up!
    """
    user_alarms = await get_user_alarms(ctx.author.id)
    alarm = next((a for a in user_alarms if a["id"] == alarm_id), None)
    if not alarm:
        await ctx.send("~_~ Alarm not found")
        return

    timezone = await get_user_timezone(ctx.author.id)
    tz = pytz.timezone(timezone)
    now = datetime.now(tz)

    repeat_candidates = {"daily", "weekly"}
    repeat = None
    message = alarm["message"]

    if "|" in raw:
        left, right = raw.split("|", 1)
        left = left.strip()
        right = right.strip()
        message = right if right else message
        tokens = left.split()
    else:
        tokens = raw.split()

    # detect repeat
    for i, t in enumerate(list(tokens)):
        tl = t.lower()
        if tl in repeat_candidates:
            repeat = tl
            tokens.pop(i)
            break

    time_str = " ".join(tokens).strip()
    if not time_str:
        await ctx.send("~_~ Provide a new time. Example: `!editalarm 2 tomorrow 9am daily | Wake up!`")
        return

    try:
        parsed_time = parser.parse(time_str, fuzzy=True, default=now)
        if parsed_time.tzinfo is None:
            parsed_time = tz.localize(parsed_time)
        if parsed_time <= now:
            parsed_time = tz.normalize(parsed_time + timedelta(days=1))

        # if user didn't mention repeat, keep existing repeat
        if repeat is None:
            repeat = alarm["repeat"]

        await update_alarm(alarm_id, parsed_time.astimezone(pytz.UTC), repeat, message)
        await ctx.send(f"✅ Alarm {alarm_id} updated to {parsed_time.strftime('%Y-%m-%d %H:%M')} ({timezone})"
                       + (f" repeat={repeat}" if repeat else ""))
    except Exception:
        await ctx.send("~_~ Could not parse that time.")

@bot.command(name='snooze')
async def snooze_command(ctx, alarm_id: int, duration: str):
    user_alarms = await get_user_alarms(ctx.author.id)
    if not any(a["id"] == alarm_id for a in user_alarms):
        await ctx.send("~_~ Alarm not found")
        return

    delta = parse_duration(duration)
    if not delta:
        await ctx.send("~_~ Invalid duration. Use like `10m`, `2h`, `1d`")
        return

    ok = await snooze_alarm(alarm_id, delta)
    await ctx.send("✅ Snoozed" if ok else "~_~ Alarm not found")

@bot.command(name='pausealarm')
async def pause_alarm_cmd(ctx, alarm_id: int):
    user_alarms = await get_user_alarms(ctx.author.id)
    if not any(a["id"] == alarm_id for a in user_alarms):
        await ctx.send("~_~ Alarm not found")
        return
    await set_alarm_paused(alarm_id, True)
    await ctx.send(f"⏸️ Alarm {alarm_id} paused")

@bot.command(name='resumealarm')
async def resume_alarm_cmd(ctx, alarm_id: int):
    user_alarms = await get_user_alarms(ctx.author.id)
    if not any(a["id"] == alarm_id for a in user_alarms):
        await ctx.send("~_~ Alarm not found")
        return
    await set_alarm_paused(alarm_id, False)
    await ctx.send(f"▶️ Alarm {alarm_id} resumed")

# ---------- Admin Logging Controls ----------
@bot.command(name='setlogchannel')
@commands.has_permissions(administrator=True)
async def set_log_channel_cmd(ctx, channel: discord.TextChannel):
    await set_log_channel(ctx.guild.id, channel.id)
    await ctx.send(f"📜 Logging channel set to {channel.mention}")

@bot.command(name='toggledeletelog')
@commands.has_permissions(administrator=True)
async def toggle_delete_log(ctx):
    new_state = await toggle_delete_logging(ctx.guild.id)
    if new_state is None:
        await ctx.send("~_~ Set a log channel first with !setlogchannel")
        return
    await ctx.send(f"🗑️ Message delete logging {'enabled ▲' if new_state else 'disabled △'}")

@bot.command(name='toggleeditlog')
@commands.has_permissions(administrator=True)
async def toggle_edit_log(ctx):
    new_state = await toggle_edit_logging(ctx.guild.id)
    if new_state is None:
        await ctx.send("~_~ Set a log channel first with !setlogchannel")
        return
    await ctx.send(f"✏️ Message edit logging {'enabled ▲' if new_state else 'disabled △'}")

@bot.command(name='togglebulkdeletelog')
@commands.has_permissions(administrator=True)
async def toggle_bulk_delete_log(ctx):
    new_state = await toggle_bulk_delete_logging(ctx.guild.id)
    if new_state is None:
        await ctx.send("~_~ Set a log channel first with !setlogchannel")
        return
    await ctx.send(f"🧹 Bulk delete logging {'enabled ▲' if new_state else 'disabled △'}")

# ---------- Event Handlers ----------
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("~_~ You don't have permission for that.")
        return
    if isinstance(error, commands.BadArgument):
        await ctx.send("~_~ Bad argument. Check the command usage with !alarmhelp")
        return
    if isinstance(error, commands.CommandNotFound):
        return
    await ctx.send("~_~ Something went wrong.")
    raise error

@bot.event
async def on_message_delete(message):
    if message.author.bot or not message.guild:
        return

    settings = await get_log_settings(message.guild.id)
    if not settings:
        return

    channel_id, log_deletes, _, _ = settings
    if not channel_id or not log_deletes:
        return

    channel = bot.get_channel(channel_id)
    if channel:
        content = (message.content or "").replace('`', "'")[:900]
        await channel.send(
            f"🗑️ Message deleted in {message.channel.mention} by {message.author.mention}:\n"
            f"```{content}```"
        )

@bot.event
async def on_bulk_message_delete(messages):
    if not messages:
        return
    first = next(iter(messages), None)
    if not first or not first.guild:
        return

    settings = await get_log_settings(first.guild.id)
    if not settings:
        return

    channel_id, _, _, log_bulk = settings
    if not channel_id or not log_bulk:
        return

    log_channel = bot.get_channel(channel_id)
    if not log_channel:
        return

    # Keep it safe/short
    sample = []
    for m in list(messages)[:10]:
        if m.author and not m.author.bot:
            sample.append(f"{m.author}: {(m.content or '')[:80]}")
    text = "\n".join(sample) if sample else "No text content (or only bots)."

    await log_channel.send(
        f"🧹 Bulk delete in {first.channel.mention} — {len(messages)} messages\n"
        f"```{text}```"
    )

@bot.event
async def on_message_edit(before, after):
    if not before.guild or before.author.bot:
        return
    if before.content == after.content:
        return

    settings = await get_log_settings(before.guild.id)
    if not settings:
        return

    channel_id, _, log_edits, _ = settings
    if not channel_id or not log_edits:
        return

    log_channel = bot.get_channel(channel_id)
    if not log_channel:
        return

    old = (before.content or "")[:800].replace("`", "'")
    new = (after.content or "")[:800].replace("`", "'")

    await log_channel.send(
        f"✏️ Message edited in {before.channel.mention} by {before.author.mention}\n"
        f"**Before:**\n```{old}```\n"
        f"**After:**\n```{new}```"
    )

@bot.event
async def on_guild_join(guild):
    try:
        invites = await guild.invites()
        guild_invites[guild.id] = {invite.code: invite for invite in invites}
    except Exception as e:
        print(f"Error fetching invites for new guild {guild}: {e}")

@bot.event
async def on_invite_create(invite):
    guild_invites.setdefault(invite.guild.id, {})
    guild_invites[invite.guild.id][invite.code] = invite

@bot.event
async def on_invite_delete(invite):
    g = invite.guild.id
    if g in guild_invites and invite.code in guild_invites[g]:
        del guild_invites[g][invite.code]

@bot.event
async def on_member_join(member):
    guild = member.guild
    settings = await get_log_settings(guild.id)
    if not settings or not settings[0]:
        return

    log_channel = bot.get_channel(settings[0])
    if not log_channel:
        return

    # --- Invite tracking (best effort) ---
    used_invite = None
    try:
        cached = guild_invites.get(guild.id, {})
        actual = {invite.code: invite for invite in await guild.invites()}
        guild_invites[guild.id] = actual

        for code, new_invite in actual.items():
            old_invite = cached.get(code)
            if not old_invite or new_invite.uses > old_invite.uses:
                used_invite = new_invite
                break
    except Exception as e:
        print(f"Invite check error: {e}")

    # --- Requested join log format ---
    # Example wanted:
    # Member joined
    # @Make it a Quote 145th to join
    # created 3 years, 10 months and 2 days ago
    # ID: 9494... • 07/01/2026 18:44

    join_pos = guild.member_count  # includes the new member
    now = datetime.now()
    created = member.created_at.replace(tzinfo=None) if member.created_at else None
    created_str = human_age(created, now) if created else "unknown"

    joined_at = member.joined_at or datetime.utcnow()
    joined_at = joined_at.replace(tzinfo=None)

    # dd/mm/YYYY HH:MM like your example
    joined_fmt = joined_at.strftime("%d/%m/%Y %H:%M")

    line1 = "**Member joined**"
    line2 = f"{member.mention} {ordinal(join_pos)} to join"
    line3 = f"created {created_str}"
    line4 = f"ID: {member.id} • {joined_fmt}"

    extra = ""
    if used_invite:
        inviter = used_invite.inviter
        extra = f"\nInvite: `{used_invite.code}` by {inviter.mention} (uses: {used_invite.uses})"

    await log_channel.send(f"{line1}\n{line2}\n{line3}\n{line4}{extra}")

@bot.event
async def on_member_remove(member):
    guild = member.guild
    settings = await get_log_settings(guild.id)
    if not settings or not settings[0]:
        return
    log_channel = bot.get_channel(settings[0])
    if log_channel:
        await log_channel.send(f"**Member left**\n{member.mention}\nID: {member.id}")

@bot.event
async def on_voice_state_update(member, before, after):
    if not member.guild:
        return

    settings = await get_log_settings(member.guild.id)
    if not settings or not settings[0]:
        return

    log_channel = bot.get_channel(settings[0])
    if not log_channel:
        return

    if before.channel == after.channel:
        return

    try:
        # If moved between channels, try detect moderator move using audit logs
        if before.channel and after.channel:
            moved_by_mod = False
            async for entry in member.guild.audit_logs(action=discord.AuditLogAction.member_update, limit=8):
                if entry.target and entry.target.id == member.id:
                    for change in entry.changes:
                        if change.key == 'voice_channel':
                            old_id = change.old_value.id if change.old_value else None
                            new_id = change.new_value.id if change.new_value else None
                            if old_id == before.channel.id and new_id == after.channel.id:
                                moved_by_mod = True
                                reason = entry.reason or "No reason provided"
                                await log_channel.send(
                                    f"🎤 {member.mention} was moved by {entry.user.mention} "
                                    f"from {before.channel.mention} to {after.channel.mention}\n"
                                    f"**Reason:** {reason}"
                                )
                                break
                    if moved_by_mod:
                        break

            if not moved_by_mod:
                await log_channel.send(f"🎤 {member.mention} moved from {before.channel.mention} to {after.channel.mention}")

        elif not before.channel and after.channel:
            await log_channel.send(f"🎤 {member.mention} joined {after.channel.mention} 🔊")

        elif before.channel and not after.channel:
            await log_channel.send(f"🎤 {member.mention} left {before.channel.mention} 🔇")

    except discord.Forbidden:
        # Missing View Audit Log etc.
        if before.channel and after.channel:
            await log_channel.send(f"🎤 {member.mention} moved from {before.channel.mention} to {after.channel.mention}")
    except Exception as e:
        print(f"Error handling voice state update: {e}")

# ---------- Alarm Checker ----------
@tasks.loop(seconds=10)
async def check_alarms():
    due_alarms = await get_due_alarms()
    for alarm in due_alarms:
        try:
            channel = bot.get_channel(alarm['channel_id']) if alarm['channel_id'] else None
            if not channel:
                # channel missing; delete one-time alarms, keep recurring but pause
                if alarm['repeat']:
                    await set_alarm_paused(alarm['id'], True)
                else:
                    await delete_alarm(alarm['id'])
                continue

            user = await bot.fetch_user(alarm['user_id'])
            await channel.send(f"🔔 {user.mention} **ALARM**: {alarm['message']}")

            if alarm['repeat']:
                next_time_utc = compute_next_recurring_utc(alarm['time'], alarm['timezone'], alarm['repeat'])
                await update_alarm_time(alarm['id'], next_time_utc)
            else:
                await delete_alarm(alarm['id'])

        except Exception as e:
            print(f"Error triggering alarm {alarm.get('id')}: {e}")
            # safest: delete one-time; pause recurring
            if alarm.get('repeat'):
                await set_alarm_paused(alarm['id'], True)
            else:
                await delete_alarm(alarm['id'])

# ---------- Startup ----------
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    await bot.change_presence(status=discord.Status.online)

    await init_db()
    if not check_alarms.is_running():
        check_alarms.start()

    # cache invites
    for guild in bot.guilds:
        try:
            invites = await guild.invites()
            guild_invites[guild.id] = {invite.code: invite for invite in invites}
        except Exception as e:
            print(f"Error initializing invites for {guild}: {e}")

try:
    bot.run(os.getenv('DISCORD_TOKEN'))
except discord.LoginFailure:
    print("~_~ Invalid token - check your DISCORD_TOKEN")
except Exception as e:
    print(f"~_~ Error starting bot: {e}")
