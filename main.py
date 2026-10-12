"""Discord entrypoint and reminders. Importing this module never starts the bot."""
import asyncio
import logging
import os
import re
from datetime import timedelta
from pathlib import Path
from zoneinfo import available_timezones

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / '.env')
import database as db
import alarm_store as alarms
from scheduling import (
    MAX_MESSAGE, anchor_for, as_utc, iso, normalize_repeat, parse_alarm_args,
    parse_duration, parse_when, quiet_end, timezone_for, utcnow, validate_message,
    validate_quiet,
)

log = logging.getLogger('alarmbot')


class AlarmBot(commands.Bot):
    async def setup_hook(self):
        await db.init_db()
        await alarms.init_db()
        for extension in ('guardian', 'community', 'privacy'):
            await self.load_extension(extension)
        self.add_dynamic_items(ReminderButton)
        self.alarm_worker = check_alarms
        check_alarms.start()
        clean_alarms.start()
        if os.getenv('SYNC_COMMANDS', 'true').lower() in {'1', 'true', 'yes'}:
            try:
                await self.tree.sync()
            except discord.HTTPException:
                log.exception('Command sync failed; prefix commands remain available. Retry sync with !synccommands.')

    async def close(self):
        check_alarms.cancel()
        clean_alarms.cancel()
        try:
            await super().close()
        finally:
            await db.close_db()


intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = AlarmBot(command_prefix='!', intents=intents, help_command=None,
               allowed_mentions=discord.AllowedMentions.none())


@bot.event
async def on_ready():
    log.info('Logged in as %s (%s), %s servers', bot.user, bot.user.id, len(bot.guilds))
    await bot.change_presence(activity=discord.Game('!help · /alarm'))


@bot.command(name='synccommands')
@commands.is_owner()
async def sync_commands(ctx):
    synced = await bot.tree.sync()
    await ctx.send(f'Synced {len(synced)} application commands.')

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
                                                        "applies protection here and in servers that explicitly trust this server. Only confirmed evidence becomes a pattern."),
        ("!uncompromised @user", "clear this server's flag and ignore accepted external flags here. Restore only unchanged Guardian-owned timeouts; preserve unrelated moderation."),
        ("!flagged", "list active flags"),
    ]),
    ("🔎 Investigation  (Moderate Members)", ("moderate_members",), [
        ("!userinfo @user", "history, join invite, staff actions and possible alt accounts in this server only (aliases: `!whois`, `!trace`)"),
    ]),
    ("📜 Logging & server setup  (Administrator)", ("administrator",), [
        ("!setuplogs #channel", "one-time setup: default log channel + every log type on (alias `!setlogchannel`)"),
        ("!setlog <category> <#channel|off|default>", "send a category to its own channel. Categories: `messages` `media` `members` `voice` `roles` `moderation` `server` `security`"),
        ("!logstatus", "show where everything goes + which bot permissions are missing"),
        ("!toggledeletelog · !toggleeditlog · !togglebulkdeletelog", "switch those message logs on/off"),
        ("!mediamirror on|off", "copy attachments into the `media` log channel as they're sent"),
        ("!protect on|off", "enable or disable network protection; receiving servers must also explicitly trust the source"),
    ]),
    ("🔒 Archive privacy  (Administrator)", ("administrator",), [
        ("!privacysettings · !archiveexclude", "configure this server's archive, retention and excluded channels/categories"),
        ("!forgetuser <user id>", "erase this server's routine archived user data; active security and moderation cases remain"),
    ]),
    ("🤝 Community", (), [
        ("/report · Message menu → Report message", "privately report an issue to this server's moderators"),
        ("/appeal", "request review of a resolved case involving you"),
        ("/event · /events · /eventcancel · /eventdelivery", "create shared events, subscribe voluntarily and choose delivery in this server"),
        ("/dataoptout · /dataexport · /forgetme", "manage your own stored data; a server command affects only this server, DM management covers your account"),
    ]),
    ("📋 Cases  (Moderate Members)", ("moderate_members",), [
        ("/cases · /case · /resolve · /caseaction", "review reports, resolve cases, record warnings or apply a local timeout"),
    ]),
    ("🛠 Community setup  (Manage Server)", ("manage_guild",), [
        ("!reportsetup · !communitysecurity · !health", "configure staff notifications, spam/raid detection and inspect setup diagnostics"),
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
    embeds = []
    async for title, rows in visible_sections(ctx, what.lower() == "all"):
        value = "\n".join(f"`{cmd}`\n└ {desc}" for cmd, desc in rows)[:1024]
        if len(embed) + len(title) + len(value) > 5500 or len(embed.fields) == 25:
            embeds.append(embed)
            embed = discord.Embed(title="Alarm Bot - more commands", color=discord.Color.blue())
        embed.add_field(name=title, value=value, inline=False)
        shown += 1
    if shown < len(HELP_SECTIONS):
        embed.set_footer(text=f"{len(HELP_SECTIONS) - shown} more section(s) need extra permissions - `!help all` lists them")
    embeds.append(embed)
    for page in embeds:
        await ctx.send(embed=page)


# Both interfaces use the same authorization, storage and scheduling paths.
def author(ctx):
    return ctx.user if isinstance(ctx, discord.Interaction) else ctx.author


def interaction_for(ctx):
    return ctx if isinstance(ctx, discord.Interaction) else ctx.interaction


def guild_id(ctx):
    return ctx.guild.id if ctx.guild else None


async def defer(ctx):
    interaction = interaction_for(ctx)
    if interaction and not interaction.response.is_done():
        await interaction.response.defer(ephemeral=True)


async def reply(ctx, content=None, *, private=False, **kwargs):
    kwargs.setdefault('allowed_mentions', discord.AllowedMentions.none())
    interaction = interaction_for(ctx)
    if interaction:
        if interaction.response.is_done():
            return await interaction.followup.send(content, ephemeral=True, **kwargs)
        return await interaction.response.send_message(content, ephemeral=True, **kwargs)
    if private and ctx.guild:
        try:
            await ctx.author.send(content, **kwargs)
            return await ctx.send('I sent your reminder information by DM.')
        except discord.Forbidden:
            return await ctx.send('Your DMs are closed. Use /alarm list or /alarm history for a private reply.')
    return await ctx.send(content, **kwargs)


class DestinationError(ValueError):
    pass


async def member_in(guild, user_id):
    # Fetch to avoid using stale membership when a user has left or been removed.
    try:
        return await guild.fetch_member(user_id)
    except (discord.NotFound, discord.Forbidden) as exc:
        raise DestinationError('You must still be a member of the reminder server.') from exc


async def destination_for(user_id, source_guild_id, destination, channel_id=None):
    guild = bot.get_guild(source_guild_id) if source_guild_id else None
    if source_guild_id and guild is None:
        raise DestinationError('The bot no longer has access to the reminder server.')
    member = await member_in(guild, user_id) if guild else None
    if destination == 'dm':
        user = bot.get_user(user_id) or await bot.fetch_user(user_id)
        return await user.create_dm()
    if not channel_id:
        raise DestinationError('Choose a channel or DM delivery.')
    try:
        channel = bot.get_channel(channel_id) or await bot.fetch_channel(channel_id)
    except (discord.NotFound, discord.Forbidden) as exc:
        raise DestinationError('The reminder channel is missing or inaccessible. Change its destination.') from exc
    if not guild or getattr(channel, 'guild', None) != guild:
        raise DestinationError('The destination must be in this server.')
    if not isinstance(channel, (discord.TextChannel, discord.Thread)):
        raise DestinationError('Choose a text channel, thread, or DM.')
    me = guild.me
    if me is None:
        raise DestinationError('The bot membership is unavailable.')
    member_perms, bot_perms = channel.permissions_for(member), channel.permissions_for(me)
    send_permission = 'send_messages_in_threads' if isinstance(channel, discord.Thread) else 'send_messages'
    if not member_perms.view_channel or not getattr(member_perms, send_permission):
        raise DestinationError('You need permission to view and send messages in the destination.')
    if not bot_perms.view_channel or not getattr(bot_perms, send_permission):
        raise DestinationError('The bot needs permission to view and send messages in the destination.')
    if isinstance(channel, discord.Thread) and channel.is_private():
        for person, perms in ((member, member_perms), (me, bot_perms)):
            if not perms.manage_threads:
                try:
                    await channel.fetch_member(person.id)
                except (discord.NotFound, discord.Forbidden) as exc:
                    raise DestinationError('You and the bot must have access to this private thread.') from exc
    return channel


async def resolve_legacy(user_id=None):
    for alarm in await alarms.pending_legacy(user_id):
        if not alarm['channel_id']:
            continue
        try:
            channel = bot.get_channel(alarm['channel_id']) or await bot.fetch_channel(alarm['channel_id'])
            if isinstance(channel, discord.DMChannel) and channel.recipient and channel.recipient.id == alarm['user_id']:
                await alarms.resolve_scope(alarm, None, 'dm')
            elif isinstance(channel, (discord.TextChannel, discord.Thread)):
                await alarms.resolve_scope(alarm, channel.guild.id, 'channel')
        except (discord.NotFound, discord.Forbidden):
            # Keep unresolvable legacy alarms out of guild lists; their owner can repair privately.
            continue


async def owned_alarm(ctx, alarm_id):
    await resolve_legacy(author(ctx).id)
    alarm = await alarms.get(alarm_id, author(ctx).id, guild_id(ctx))
    if alarm is None:
        raise ValueError('Reminder not found in this server or it belongs to someone else. Your DMs offer private management of all your reminders.')
    return alarm


def summary(alarm):
    due = as_utc(alarm['snoozed_until_utc'] or alarm['time_utc'])
    stamp = int(due.timestamp())
    destination = 'DM' if alarm['destination'] == 'dm' else f"<#{alarm['channel_id']}>"
    repeat = alarm['repeat'] or 'once'
    return f"Reminder **#{alarm['id']}** · <t:{stamp}:F> (<t:{stamp}:R>)\nTimezone: {alarm['timezone']} · Repeat: {repeat} · Delivery: {destination}"


async def create_core(ctx, when_text, repeat, message, delivery='here', channel=None, until_text=None):
    await defer(ctx)
    tz_name = await db.get_user_timezone(author(ctx).id)
    when = parse_when(when_text, timezone_for(tz_name))
    if when is None:
        raise ValueError('Choose a future time, such as tomorrow 9am or in 2h.')
    until = parse_when(until_text, timezone_for(tz_name)) if until_text else None
    if until_text and until is None:
        raise ValueError('The end date must be a future date.')
    if delivery not in {'here', 'dm'}:
        raise ValueError('Delivery must be here or dm.')
    if channel is not None and delivery == 'dm':
        raise ValueError('Choose either a channel or DM delivery.')
    destination = 'dm' if delivery == 'dm' or ctx.guild is None else 'channel'
    channel_id = getattr(channel or ctx.channel, 'id', None) if destination == 'channel' else None
    checked = await destination_for(author(ctx).id, guild_id(ctx), destination, channel_id)
    alarm = await alarms.add(author(ctx).id, guild_id(ctx), checked.id, destination,
                             when, tz_name, repeat, message, until)
    await reply(ctx, 'Created ' + summary(alarm) + '\n' + discord.utils.escape_markdown(alarm['message']),
                view=ReminderView(alarm['id']))
    return alarm


async def edit_core(ctx, alarm_id, raw, until_text=None):
    await defer(ctx)
    alarm = await owned_alarm(ctx, alarm_id)
    tz_name = await db.get_user_timezone(author(ctx).id)
    when, repeat, message = parse_alarm_args(raw, timezone_for(tz_name))
    until = as_utc(alarm['until_utc']) if alarm['until_utc'] else None
    if until_text is not None:
        until = None if until_text.lower() == 'off' else parse_when(until_text, timezone_for(tz_name))
        if until is None and until_text.lower() != 'off':
            raise ValueError('Use a future end date or off.')
    await destination_for(author(ctx).id, alarm['guild_id'], alarm['destination'], alarm['channel_id'])
    alarm = await alarms.edit(alarm, when, tz_name, alarm['repeat'] if repeat is None else repeat,
                              message or alarm['message'], until)
    await reply(ctx, 'Updated ' + summary(alarm))


async def action_core(ctx, alarm_id, action, duration=None):
    await defer(ctx)
    alarm = await owned_alarm(ctx, alarm_id)
    if action in {'resume', 'snooze'}:
        await destination_for(author(ctx).id, alarm['guild_id'], alarm['destination'], alarm['channel_id'])
    if action == 'snooze':
        delta = parse_duration(duration or '10m')
        if not delta:
            raise ValueError('Use a duration between 1 minute and 365 days, such as 10m or 2h.')
        alarm = await alarms.snooze(alarm, delta)
    elif action == 'done':
        alarm = await alarms.done(alarm)
    elif action == 'delete':
        await alarms.delete(alarm)
        return await reply(ctx, f'Reminder #{alarm_id} deleted.')
    elif action == 'pause':
        alarm = await alarms.mutate(alarm, {'paused': 1, 'state': 'active'})
    elif action == 'resume':
        alarm = await alarms.mutate(alarm, {'paused': 0, 'state': 'active', 'attempts': 0, 'last_error': None, 'next_attempt_utc': None})
    else:
        raise ValueError('Unknown reminder action.')
    await reply(ctx, f"Reminder #{alarm_id}: {action}." + ('\n' + summary(alarm) if action in {'snooze', 'resume'} else ''))


async def list_core(ctx, page=1):
    await defer(ctx)
    if page < 1:
        raise ValueError('Page numbers start at 1.')
    await resolve_legacy(author(ctx).id)
    rows, total = await alarms.list_for(author(ctx).id, guild_id(ctx), page)
    if not rows:
        return await reply(ctx, 'No reminders on this page.', private=True)
    embed = discord.Embed(title=f'Your reminders · page {page}/{max(1,(total+4)//5)}', color=discord.Color.gold())
    for alarm in rows:
        state = 'paused' if alarm['paused'] else alarm['state']
        value = summary(alarm) + '\n' + discord.utils.escape_markdown(alarm['message'][:250])
        if alarm['last_error']:
            value += '\nLast error: ' + discord.utils.escape_markdown(alarm['last_error'][:120])
        embed.add_field(name=f"#{alarm['id']} · {state}", value=value[:1024], inline=False)
    embed.set_footer(text='Private DM management includes all of your reminders. Guild lists include only this server.')
    await reply(ctx, private=True, embed=embed)


async def history_core(ctx, page=1):
    await defer(ctx)
    if page < 1:
        raise ValueError('Page numbers start at 1.')
    rows = await alarms.history(author(ctx).id, guild_id(ctx), page)
    lines = [f"**#{row['alarm_id']} · {row['outcome']}** <t:{int(as_utc(row['occurred_at_utc']).timestamp())}:R>\n{discord.utils.escape_markdown(row['detail'] or '')}" for row in rows]
    await reply(ctx, private=True, embed=discord.Embed(title=f'Your reminder history · page {page}', description='\n\n'.join(lines) or 'No delivery history.'))


async def destination_core(ctx, alarm_id, delivery='here', channel=None):
    await defer(ctx)
    alarm = await owned_alarm(ctx, alarm_id)
    if delivery not in {'here', 'dm'}:
        raise ValueError('Delivery must be here or dm.')
    if channel is not None and delivery == 'dm':
        raise ValueError('Choose a channel or DM, not both.')
    destination = 'dm' if delivery == 'dm' or ctx.guild is None else 'channel'
    # Private self-service can recover reminders after a server or membership is lost.
    target_guild_id = guild_id(ctx)
    channel_id = getattr(channel or ctx.channel, 'id', None) if destination == 'channel' else None
    checked = await destination_for(author(ctx).id, target_guild_id, destination, channel_id)
    alarm = await alarms.mutate(alarm, dict(destination=destination,channel_id=checked.id,guild_id=target_guild_id,
        scope_known=1,state='active',attempts=0,last_error=None,next_attempt_utc=None))
    await reply(ctx, 'Updated destination. ' + summary(alarm))


async def quiet_core(ctx, start, end=''):
    start, end = validate_quiet(start, end)
    await alarms.set_quiet(author(ctx).id, start, end)
    zone = await db.get_user_timezone(author(ctx).id)
    await reply(ctx, f'Quiet hours: {start}–{end} ({zone}). Due reminders wait until quiet hours end.' if start else 'Quiet hours disabled.')


@bot.hybrid_command(name='settimezone')
async def set_timezone(ctx, timezone: str):
    """Set your reminder timezone. Existing schedules keep their zone until edited."""
    timezone_for(timezone)
    await db.set_user_timezone(ctx.author.id, timezone)
    await reply(ctx, f'Timezone set to {timezone}. Existing reminder schedules retain their timezone until edited.')


@set_timezone.autocomplete('timezone')
async def timezone_autocomplete(interaction, current):
    return [app_commands.Choice(name=name,value=name) for name in sorted(available_timezones()) if current.lower() in name.lower()][:25]


@bot.hybrid_command(name='gettimezone')
async def get_timezone(ctx):
    """Show your timezone."""
    await reply(ctx, f'Your timezone: {await db.get_user_timezone(ctx.author.id)}')


@bot.command(name='setalarm')
@commands.cooldown(5, 30, commands.BucketType.user)
async def set_alarm(ctx, *, raw: str):
    tz_name = await db.get_user_timezone(ctx.author.id)
    when, repeat, message = parse_alarm_args(raw, timezone_for(tz_name))
    await create_core(ctx, when.isoformat(), repeat, message or 'Alarm!')


@bot.command(name='dmalarm')
@commands.cooldown(5, 30, commands.BucketType.user)
async def dm_alarm(ctx, *, raw: str):
    tz_name = await db.get_user_timezone(ctx.author.id)
    when, repeat, message = parse_alarm_args(raw, timezone_for(tz_name))
    await create_core(ctx, when.isoformat(), repeat, message or 'Alarm!', 'dm')


@bot.command(name='listalarms')
async def list_alarms(ctx, page: int=1):
    await list_core(ctx, page)


@bot.command(name='alarmhistory')
async def alarm_history(ctx, page: int=1):
    await history_core(ctx, page)


@bot.command(name='editalarm')
@commands.cooldown(10, 30, commands.BucketType.user)
async def edit_alarm(ctx, alarm_id: int, *, raw: str):
    await edit_core(ctx, alarm_id, raw)


@bot.command(name='deletealarm')
async def delete_alarm_command(ctx, alarm_id: int):
    await action_core(ctx, alarm_id, 'delete')


@bot.command(name='snooze')
@commands.cooldown(10, 30, commands.BucketType.user)
async def snooze_command(ctx, alarm_id: int, duration: str):
    await action_core(ctx, alarm_id, 'snooze', duration)


@bot.command(name='donealarm')
async def done_alarm(ctx, alarm_id: int):
    await action_core(ctx, alarm_id, 'done')


@bot.command(name='pausealarm')
async def pause_alarm(ctx, alarm_id: int):
    await action_core(ctx, alarm_id, 'pause')


@bot.command(name='resumealarm')
async def resume_alarm(ctx, alarm_id: int):
    await action_core(ctx, alarm_id, 'resume')


@bot.command(name='alarmdestination')
async def alarm_destination(ctx, alarm_id: int, destination: str='here'):
    channel = None
    if destination not in {'here', 'dm'}:
        channel = await commands.TextChannelConverter().convert(ctx, destination)
    await destination_core(ctx, alarm_id, 'dm' if destination == 'dm' else 'here', channel)


@bot.command(name='quiethours')
async def quiet_hours(ctx, start: str, end: str=''):
    await quiet_core(ctx, start, end)

_reminder_limits = commands.CooldownMapping.from_cooldown(10, 30, commands.BucketType.user)


def check_rate(user):
    from types import SimpleNamespace
    retry = _reminder_limits.get_bucket(SimpleNamespace(author=user)).update_rate_limit()
    if retry:
        raise ValueError(f'Too many reminder actions. Try again in {retry:.0f} seconds.')


class AlarmGroup(app_commands.Group):
    async def interaction_check(self, interaction):
        try:
            check_rate(interaction.user)
            return True
        except ValueError as exc:
            await reply(interaction, str(exc))
            return False

    async def on_error(self, interaction, error):
        await interaction_error(interaction, error)


alarm_group = AlarmGroup(name='alarm', description='Create and manage private or server reminders')
bot.tree.add_command(alarm_group)


@alarm_group.command(name='create', description='Create a reminder with an exact schedule preview')
@app_commands.describe(when='tomorrow 9am, in 2h, or 2030-01-05 18:00', repeat='once, daily, weekly, weekdays, monthly, or mon,wed,fri',
                       delivery='here or dm', until='Optional end date (exclusive)')
@app_commands.choices(delivery=[app_commands.Choice(name='Current / selected channel', value='here'),app_commands.Choice(name='Private DM',value='dm')])
async def slash_create(interaction: discord.Interaction, when: str, message: str='Alarm!', repeat: str='once',
                       delivery: str='here', channel: discord.TextChannel|None=None, until: str|None=None):
    await create_core(interaction, when, repeat, message, delivery, channel, until)


@alarm_group.command(name='edit', description='Edit time, repeat or message; use once to stop repeating')
async def slash_edit(interaction: discord.Interaction, alarm_id: int, schedule: str, until: str|None=None):
    await edit_core(interaction, alarm_id, schedule, until)


@alarm_group.command(name='list', description='Privately list your reminders in this server')
async def slash_list(interaction: discord.Interaction, page: int=1):
    await list_core(interaction, page)


@alarm_group.command(name='history', description='Privately inspect deliveries, retries and failures')
async def slash_history(interaction: discord.Interaction, page: int=1):
    await history_core(interaction, page)


@alarm_group.command(name='snooze', description='Snooze this occurrence without shifting the repeating schedule')
async def slash_snooze(interaction: discord.Interaction, alarm_id: int, duration: str='10m'):
    await action_core(interaction, alarm_id, 'snooze', duration)


@alarm_group.command(name='done', description='Dismiss this occurrence; keep the next repeating occurrence')
async def slash_done(interaction: discord.Interaction, alarm_id: int):
    await action_core(interaction, alarm_id, 'done')


@alarm_group.command(name='pause', description='Pause a reminder')
async def slash_pause(interaction: discord.Interaction, alarm_id: int):
    await action_core(interaction, alarm_id, 'pause')


@alarm_group.command(name='resume', description='Resume a paused or failed reminder')
async def slash_resume(interaction: discord.Interaction, alarm_id: int):
    await action_core(interaction, alarm_id, 'resume')


@alarm_group.command(name='delete', description='Delete a reminder you own')
async def slash_delete(interaction: discord.Interaction, alarm_id: int):
    await action_core(interaction, alarm_id, 'delete')


@alarm_group.command(name='destination', description='Repair or change your reminder destination')
@app_commands.choices(delivery=[app_commands.Choice(name='Current / selected channel',value='here'),app_commands.Choice(name='Private DM',value='dm')])
async def slash_destination(interaction: discord.Interaction, alarm_id: int, delivery: str='here', channel: discord.TextChannel|None=None):
    await destination_core(interaction, alarm_id, delivery, channel)


@alarm_group.command(name='quiet', description='Defer reminders during your local quiet hours; use off to disable')
async def slash_quiet(interaction: discord.Interaction, start: str, end: str=''):
    await quiet_core(interaction, start, end)


async def status_core(ctx, alarm_id):
    await defer(ctx)
    alarm = await owned_alarm(ctx, alarm_id)
    state = 'paused' if alarm['paused'] else alarm['state']
    content = summary(alarm) + f"\nStatus: **{state}** · Attempts: {alarm['attempts']}/{alarms.MAX_ATTEMPTS}"
    if alarm['next_attempt_utc']:
        content += f"\nNext delivery attempt: <t:{int(as_utc(alarm['next_attempt_utc']).timestamp())}:R>"
    if alarm['last_error']:
        content += '\nLast error: ' + discord.utils.escape_markdown(alarm['last_error'])
    await reply(ctx, content, private=True, view=ReminderView(alarm_id))


@alarm_group.command(name='status', description='Privately inspect next delivery and retry status')
async def slash_status(interaction: discord.Interaction, alarm_id: int):
    await status_core(interaction, alarm_id)


@bot.command(name='alarmstatus')
async def alarm_status(ctx, alarm_id: int):
    await status_core(ctx, alarm_id)


class RescheduleModal(discord.ui.Modal, title='Reschedule reminder'):
    schedule = discord.ui.TextInput(label='Time [repeat] | optional message', placeholder='tomorrow 9am weekdays | Take a break',max_length=1600)

    def __init__(self, alarm_id):
        super().__init__()
        self.alarm_id = alarm_id

    async def on_submit(self, interaction):
        try:
            check_rate(interaction.user)
            await edit_core(interaction, self.alarm_id, str(self.schedule))
        except Exception as exc:
            await interaction_error(interaction, exc)


class ReminderButton(discord.ui.DynamicItem[discord.ui.Button], template=r'alarm:(?P<action>snooze|done|reschedule):(?P<id>[0-9]+)'):
    def __init__(self, alarm_id, action):
        labels = {'snooze':'Snooze 10m','done':'Done','reschedule':'Reschedule'}
        super().__init__(discord.ui.Button(label=labels[action],style=discord.ButtonStyle.secondary,custom_id=f'alarm:{action}:{alarm_id}'))
        self.alarm_id, self.action = alarm_id, action

    @classmethod
    async def from_custom_id(cls, interaction, item, match):
        return cls(int(match['id']), match['action'])

    async def callback(self, interaction):
        try:
            check_rate(interaction.user)
            if self.action == 'reschedule':
                # Modal must be the first response, so don't defer until the modal is submitted.
                await owned_alarm(interaction, self.alarm_id)
                await interaction.response.send_modal(RescheduleModal(self.alarm_id))
            else:
                await action_core(interaction, self.alarm_id, self.action, '10m')
        except Exception as exc:
            await interaction_error(interaction, exc)


class ReminderView(discord.ui.View):
    def __init__(self, alarm_id):
        super().__init__(timeout=None)
        for action in ('snooze', 'done', 'reschedule'):
            self.add_item(ReminderButton(alarm_id, action))


class RemindMessageModal(discord.ui.Modal, title='Remind me about this message'):
    when = discord.ui.TextInput(label='When?',placeholder='in 2h or tomorrow 9am',max_length=100)

    def __init__(self, message):
        super().__init__()
        self.reminder_text = (message.content[:900] or 'Revisit this message') + '\n' + message.jump_url

    async def on_submit(self, interaction):
        try:
            check_rate(interaction.user)
            await create_core(interaction, str(self.when), 'once', self.reminder_text, 'dm')
        except Exception as exc:
            await interaction_error(interaction, exc)


@bot.tree.context_menu(name='Remind me')
async def remind_message(interaction: discord.Interaction, message: discord.Message):
    check_rate(interaction.user)
    if message.guild and (message.guild != interaction.guild or not message.channel.permissions_for(interaction.user).view_channel):
        raise ValueError('You must be able to view this message.')
    await interaction.response.send_modal(RemindMessageModal(message))


# This task survives transient database/network failures and persists retry state.
async def notify_failed(alarm):
    try:
        user = bot.get_user(alarm['user_id']) or await bot.fetch_user(alarm['user_id'])
        await user.send(f"Reminder #{alarm['id']} could not be delivered. It has been retained. "
                        'Use /alarm status and /alarm destination to inspect and repair it, then /alarm resume.',
                        allowed_mentions=discord.AllowedMentions.none())
    except discord.HTTPException:
        log.info('Could not DM failed reminder notice for %s', alarm['id'])


async def deliver_one(alarm):
    if not alarm['scope_known']:
        await resolve_legacy(alarm['user_id'])
        alarm = await alarms.get(alarm['id'])
        if alarm is None:
            return
    alarm = await alarms.claim(alarm)
    if alarm is None:
        return
    try:
        now = utcnow()
        if alarm['until_utc'] and now >= as_utc(alarm['until_utc']):
            await alarms.mutate(alarm, {'state':'done'})
            await alarms.record(alarm, 'expired', 'Schedule end reached before delivery.')
            return
        if not alarm['scope_known']:
            raise DestinationError('Legacy destination is inaccessible. Repair it using private reminder management.')
        prefs = await alarms.preferences(alarm['user_id'])
        quiet_zone = await db.get_user_timezone(alarm['user_id'])
        wait_until = quiet_end(now, quiet_zone, prefs.get('quiet_start'), prefs.get('quiet_end'))
        if wait_until:
            await alarms.defer(alarm, wait_until)
            return
        channel = await destination_for(alarm['user_id'], alarm['guild_id'], alarm['destination'], alarm['channel_id'])
        # Check the lease again after network lookups so canceled/edited reminders aren't sent.
        current = await alarms.get(alarm['id'])
        if current is None or current['lease_token'] != alarm['lease_token']:
            return
        scheduled = as_utc(alarm['snoozed_until_utc'] or alarm['time_utc'])
        late = ' (delayed)' if now-scheduled > timedelta(minutes=1) else ''
        await asyncio.wait_for(channel.send(
            f"🔔 <@{alarm['user_id']}> **REMINDER #{alarm['id']}**{late}: {alarm['message']}",
            allowed_mentions=discord.AllowedMentions(everyone=False,roles=False,users=[discord.Object(id=alarm['user_id'])],replied_user=False),
            view=ReminderView(alarm['id'])), timeout=45)
        await alarms.delivered(alarm, utcnow())
    except Exception as exc:
        permanent = isinstance(exc, (DestinationError, discord.Forbidden, discord.NotFound))
        stopped = await alarms.failed(alarm, str(exc), permanent=permanent)
        log.warning('Reminder %s delivery failed (%s): %s', alarm['id'],type(exc).__name__,exc)
        if stopped:
            await notify_failed(alarm)


@tasks.loop(seconds=10)
async def check_alarms():
    try:
        due = await alarms.due()
    except Exception:
        log.exception('Reminder scan failed; the next scan will retry.')
        return
    for alarm in due:
        try:
            await deliver_one(alarm)
        except Exception:
            # Failure recording can itself fail; the persisted lease expires for recovery.
            log.exception('Reminder worker failed for %s; it will recover on a later scan.', alarm['id'])


@check_alarms.before_loop
async def before_alarms():
    await bot.wait_until_ready()


@tasks.loop(hours=1)
async def clean_alarms():
    try:
        await alarms.cleanup()
    except Exception:
        log.exception('Reminder cleanup failed; retrying next hour.')


@clean_alarms.before_loop
async def before_cleanup():
    await bot.wait_until_ready()


async def interaction_error(interaction, error):
    original = getattr(error, 'original', error)
    if isinstance(original, ValueError):
        return await reply(interaction, str(original))
    if isinstance(original, app_commands.CheckFailure):
        return await reply(interaction, 'You cannot use that command here.')
    log.error('Application command failed',exc_info=(type(original),original,original.__traceback__))
    await reply(interaction, 'The action failed. Your saved reminders are retained; please try again.')


@bot.tree.error
async def on_app_command_error(interaction, error):
    await interaction_error(interaction, error)


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    original = getattr(error,'original',error)
    if isinstance(original, ValueError):
        return await reply(ctx,str(original))
    if isinstance(error,commands.CommandOnCooldown):
        return await reply(ctx,f'Try again in {error.retry_after:.0f} seconds.')
    if isinstance(error,(commands.MissingPermissions,commands.NotOwner,commands.CheckFailure)):
        return await reply(ctx,'You do not have permission to use that command here.')
    if isinstance(error,(commands.MissingRequiredArgument,commands.BadArgument)):
        return await reply(ctx,f'Check !help for command usage. {error}')
    log.error('Prefix command failed',exc_info=(type(original),original,original.__traceback__))
    await reply(ctx,'The command failed. Please try again.')


HELP_SECTIONS.insert(1, ('📅 More reminders', (), [
    ('/alarm create · /alarm edit', 'Choose channel/DM delivery, end date, and once/daily/weekly/weekdays/monthly/mon,wed,fri repeats.'),
    ('!dmalarm <time> [repeat] | message', 'Private delivery. !listalarms and !alarmhistory send private lists; add a page number.'),
    ('!alarmdestination <id> <here|dm|#channel>', 'Repair a missing channel or change the destination.'),
    ('!alarmstatus <id> · !donealarm <id>', 'See delivery status or dismiss this occurrence. Buttons offer Snooze, Done and Reschedule.'),
    ('!quiethours <22:00> <08:00> · !quiethours off', 'Wait until quiet hours end, in your timezone.'),
    ('Message menu → Remind me', 'Create a private reminder containing a link to a message.'),
]))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    token = os.getenv('DISCORD_TOKEN')
    if not token:
        raise SystemExit('DISCORD_TOKEN is missing; set it in .env or the process environment.')
    try:
        bot.run(token)
    except discord.LoginFailure:
        raise SystemExit('Invalid Discord token. Check DISCORD_TOKEN.')
