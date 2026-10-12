"""Private reports, local safety alerts and voluntary community event reminders."""
import asyncio
import collections
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Literal

import discord
import pytz
from discord import app_commands
from discord.ext import commands, tasks

import database as db
import community_store as store

log = logging.getLogger(__name__)
NO_MENTIONS = discord.AllowedMentions.none()


def staff(member):
    return isinstance(member, discord.Member) and member.guild_permissions.moderate_members


def can_manage_event(member, event):
    return (isinstance(member, discord.Member) and member.guild.id == event['guild_id'] and
            (member.id == event['creator_id'] or member.guild_permissions.manage_events or
             member.guild_permissions.manage_guild))


def event_time(value, tz_name, now=None):
    """ISO local date/time or explicit UTC offset; reject ambiguous DST times."""
    when = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
    if when.tzinfo is None:
        when = pytz.timezone(tz_name).localize(when, is_dst=None)
    when = when.astimezone(timezone.utc)
    now = now or datetime.now(timezone.utc)
    if not now + timedelta(seconds=30) <= when <= now + timedelta(days=366):
        raise ValueError('Choose a time between 30 seconds and 366 days from now.')
    return when


class FloodWindow:
    """Bound both tracked actors and samples; keep cooldowns with the actor entry."""
    def __init__(self, capacity=10000, max_samples=101):
        self.entries = collections.OrderedDict()
        self.capacity = capacity
        self.max_samples = max_samples

    def check(self, key, now, window, message_limit, mention_limit=None, mentions=0, cooldown=60):
        samples, last_alert = self.entries.pop(key, (collections.deque(maxlen=self.max_samples), float('-inf')))
        while samples and samples[0][0] <= now - window:
            samples.popleft()
        samples.append((now, mentions))
        over = len(samples) >= message_limit or (mention_limit is not None and sum(n for _, n in samples) >= mention_limit)
        alert = over and now - last_alert >= cooldown
        self.entries[key] = (samples, now if alert else last_alert)
        while len(self.entries) > self.capacity:
            self.entries.popitem(last=False)
        return over, alert


class EventSubscriptionView(discord.ui.View):
    def __init__(self, cog, event_id):
        super().__init__(timeout=None)
        self.cog, self.event_id = cog, event_id
        join = discord.ui.Button(label='Subscribe', style=discord.ButtonStyle.success,
                                 custom_id=f'community:event:join:{event_id}')
        leave = discord.ui.Button(label='Unsubscribe', style=discord.ButtonStyle.secondary,
                                  custom_id=f'community:event:leave:{event_id}')
        join.callback = self.subscribe
        leave.callback = self.unsubscribe
        self.add_item(join)
        self.add_item(leave)

    async def subscribe(self, interaction):
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return await interaction.response.send_message('Use this in the event server.', ephemeral=True)
        event = await store.get_event(interaction.guild_id, self.event_id)
        channel = interaction.guild.get_channel(event['channel_id']) if event else None
        if not channel or not channel.permissions_for(interaction.user).view_channel:
            return await interaction.response.send_message('This event is unavailable.', ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        dm = await store.subscribe(interaction.guild_id, self.event_id, interaction.user.id)
        if dm is None:
            message = 'This event has started, was cancelled, or reached its 80-subscriber limit.'
        else:
            message = ('Subscribed: you opted into a DM reminder.' if dm else
                       'Subscribed: you will be mentioned here at the start. Use /eventdelivery to opt into DMs.')
        await interaction.followup.send(message, ephemeral=True, allowed_mentions=NO_MENTIONS)

    async def unsubscribe(self, interaction):
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return await interaction.response.send_message('Use this in the event server.', ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        await store.unsubscribe(interaction.guild_id, self.event_id, interaction.user.id)
        await interaction.followup.send('Unsubscribed. Pending reminders for you will be skipped.', ephemeral=True)


class ReportModal(discord.ui.Modal, title='Report this message privately'):
    reason = discord.ui.TextInput(label='What should moderators review?', style=discord.TextStyle.paragraph,
                                 min_length=5, max_length=1800)

    def __init__(self, cog, message):
        super().__init__(timeout=300)
        self.cog, self.message = cog, message

    async def on_submit(self, interaction):
        message = self.message
        if not interaction.guild or message.guild.id != interaction.guild_id:
            return await interaction.response.send_message('Reports must stay in this server.', ephemeral=True)
        channel = interaction.guild.get_channel_or_thread(message.channel.id)
        if not channel or not channel.permissions_for(interaction.user).view_channel:
            return await interaction.response.send_message('You can no longer access this message.', ephemeral=True)
        evidence = message.content[:1400]
        if message.attachments:
            evidence += '\nAttachments: ' + ', '.join(a.filename for a in message.attachments)[:350]
        await self.cog.submit_report(interaction, message.author.id, str(self.reason), evidence, message.jump_url)


class Community(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.settings = {}
        self.flood = FloodWindow()
        self.joins = FloodWindow(capacity=2000)
        self.report_limits = FloodWindow(capacity=10000)
        self.queue = asyncio.Queue(maxsize=100)
        self.worker = None
        self.last_delivery_error = None
        self.views = {}
        self.report_menu = app_commands.ContextMenu(name='Report message', callback=self.report_message)

    async def cog_load(self):
        await store.init_db()
        self.settings = await store.security_settings()
        self.bot.tree.add_command(self.report_menu)
        for event in await store.active_events():
            if event['message_id']:
                view = EventSubscriptionView(self, event['id'])
                self.views[event['id']] = view
                self.bot.add_view(view, message_id=event['message_id'])
        self.worker = asyncio.create_task(self.alert_worker(), name='community-alerts')
        self.deliver_events.start()

    async def cog_unload(self):
        pending = [self.deliver_events.get_task(), self.worker]
        self.deliver_events.cancel()
        if self.worker:
            self.worker.cancel()
        await asyncio.gather(*(task for task in pending if task), return_exceptions=True)
        for view in self.views.values():
            view.stop()
        self.bot.tree.remove_command(self.report_menu.name, type=self.report_menu.type)

    async def cog_app_command_error(self, interaction, error):
        if isinstance(error, (app_commands.MissingPermissions, app_commands.CheckFailure)):
            message = 'You do not have permission to use this command here.'
        else:
            log.error('Community command failed: %s', type(error).__name__)
            message = 'The operation failed. Please try again; a moderator can check /health.'
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True, allowed_mentions=NO_MENTIONS)
        else:
            await interaction.response.send_message(message, ephemeral=True, allowed_mentions=NO_MENTIONS)

    async def require_staff(self, interaction):
        if not interaction.guild or not staff(interaction.user):
            await interaction.response.send_message('Current-server Moderate Members permission is required.', ephemeral=True)
            return False
        return True

    async def notify_case(self, guild, case_id, kind='New report'):
        channel_id = await store.report_channel(guild.id)
        channel = guild.get_channel(channel_id) if channel_id else None
        if channel:
            try:
                # Details remain private in /case, even if channel access changes later.
                await channel.send(f'{kind}: case #{case_id}. Staff can privately review it with /case.', allowed_mentions=NO_MENTIONS)
            except discord.HTTPException:
                log.warning('Case notification delivery failed for guild %s', guild.id)

    async def submit_report(self, interaction, target_id, reason, evidence='', message_url=None):
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return await interaction.response.send_message('Reports are available inside a server.', ephemeral=True)
        if not 5 <= len(reason.strip()) <= 1800:
            return await interaction.response.send_message('Give a reason between 5 and 1800 characters.', ephemeral=True)
        _, limited = self.report_limits.check((interaction.guild_id, interaction.user.id), time.monotonic(), 600, 4, cooldown=0)
        if limited:
            return await interaction.response.send_message('You can submit up to three reports every ten minutes.', ephemeral=True)
        if not await store.report_channel(interaction.guild_id):
            return await interaction.response.send_message('A server manager needs to run /reportsetup first.', ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        case_id = await store.create_case(interaction.guild_id, interaction.user.id, target_id, reason.strip(), evidence, message_url)
        await interaction.followup.send(f'Private report saved as case #{case_id}. Moderators in this server can review it.', ephemeral=True)
        await self.notify_case(interaction.guild, case_id)

    @app_commands.command(name='report', description='Send a private report to this server’s moderators.')
    @app_commands.guild_only()
    async def report(self, interaction: discord.Interaction, member: discord.Member, reason: str):
        await self.submit_report(interaction, member.id, reason)

    async def report_message(self, interaction: discord.Interaction, message: discord.Message):
        if not interaction.guild or not message.guild or message.guild.id != interaction.guild_id:
            return await interaction.response.send_message('Reports must stay in this server.', ephemeral=True)
        if not message.channel.permissions_for(interaction.user).view_channel:
            return await interaction.response.send_message('You cannot access this message.', ephemeral=True)
        await interaction.response.send_modal(ReportModal(self, message))

    @commands.hybrid_command(name='reportsetup', description='Set the private staff channel for case notifications.')
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def reportsetup(self, ctx, channel: discord.TextChannel):
        if channel.guild.id != ctx.guild.id or channel.permissions_for(ctx.guild.default_role).view_channel:
            return await ctx.send('Choose a private staff channel in this server; @everyone must not have View Channel.', ephemeral=True)
        if not channel.permissions_for(ctx.guild.me).send_messages or not channel.permissions_for(ctx.author).view_channel:
            return await ctx.send('You need access to that channel, and the bot must be able to send there.', ephemeral=True)
        await store.set_report_channel(ctx.guild.id, channel.id)
        await ctx.send('Report notifications configured. Members can use /report or the Report message context menu.', ephemeral=True)

    @app_commands.command(name='cases', description='Privately list this server’s moderation cases.')
    @app_commands.guild_only()
    @app_commands.default_permissions(moderate_members=True)
    async def cases(self, interaction: discord.Interaction, state: Literal['open', 'appealed', 'resolved'] = 'open'):
        if not await self.require_staff(interaction):
            return
        await interaction.response.defer(ephemeral=True)
        rows = await store.list_cases(interaction.guild_id, state)
        lines = [f"#{r['id']} · user {r['target_id']} · {r['created_at'][:10]}" for r in rows]
        await interaction.followup.send('\n'.join(lines) or 'No cases in this state.', ephemeral=True, allowed_mentions=NO_MENTIONS)

    @app_commands.command(name='case', description='Privately review a case and its local staff action history.')
    @app_commands.guild_only()
    @app_commands.default_permissions(moderate_members=True)
    async def case(self, interaction: discord.Interaction, case_id: int):
        if not await self.require_staff(interaction):
            return
        await interaction.response.defer(ephemeral=True)
        case = await store.get_case(interaction.guild_id, case_id)
        if not case:
            return await interaction.followup.send('Case not found in this server.', ephemeral=True)
        emb = discord.Embed(title=f"Case #{case_id} · {case['state']}", description=case['reason'][:1800], color=discord.Color.orange())
        emb.add_field(name='Reporter / subject IDs', value=f"{case['reporter_id']} / {case['target_id']}", inline=False)
        if case['evidence']:
            emb.add_field(name='Evidence snapshot', value=case['evidence'][:1000], inline=False)
        if case['message_url']:
            emb.add_field(name='Original message', value=case['message_url'], inline=False)
        if case['resolution']:
            emb.add_field(name='Resolution', value=case['resolution'][:1000], inline=False)
        actions = await store.case_actions(interaction.guild_id, case_id)
        if actions:
            emb.add_field(name='Recent actions', value='\n'.join(f"{a['action']} · {a['actor_id']}: {a['note'][:160]}" for a in actions)[:1000], inline=False)
        await interaction.followup.send(embed=emb, ephemeral=True, allowed_mentions=NO_MENTIONS)

    @app_commands.command(name='resolve', description='Resolve a report or appeal in this server.')
    @app_commands.guild_only()
    @app_commands.default_permissions(moderate_members=True)
    async def resolve(self, interaction: discord.Interaction, case_id: int, resolution: str):
        if not await self.require_staff(interaction):
            return
        if not 5 <= len(resolution.strip()) <= 1800:
            return await interaction.response.send_message('Resolution must contain 5–1800 characters.', ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        case = await store.get_case(interaction.guild_id, case_id)
        if case and case['state'] == 'appealed' and case['resolved_by'] == interaction.user.id:
            return await interaction.followup.send('An appeal needs a different moderator to review it.', ephemeral=True)
        changed = await store.resolve_case(interaction.guild_id, case_id, interaction.user.id, resolution.strip())
        await interaction.followup.send('Case resolved. The reporter or subject can use /appeal with this case ID.' if changed else 'No open case with that ID in this server.', ephemeral=True)

    @app_commands.command(name='appeal', description='Ask for another moderator to review a resolved case involving you.')
    @app_commands.guild_only()
    async def appeal(self, interaction: discord.Interaction, case_id: int, explanation: str):
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return await interaction.response.send_message('Use this inside the case’s server.', ephemeral=True)
        if not 5 <= len(explanation.strip()) <= 1800:
            return await interaction.response.send_message('Explain your appeal in 5–1800 characters.', ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        changed = await store.appeal_case(interaction.guild_id, case_id, interaction.user.id, explanation.strip())
        await interaction.followup.send('Appeal submitted for a different moderator to review.' if changed else 'No resolved case involving you with that ID in this server.', ephemeral=True)
        if changed:
            await self.notify_case(interaction.guild, case_id, 'New appeal')

    @app_commands.command(name='caseaction', description='Record a note, warn a member, or apply a local timeout for a case.')
    @app_commands.guild_only()
    @app_commands.default_permissions(moderate_members=True)
    async def caseaction(self, interaction: discord.Interaction, case_id: int,
                         action: Literal['note', 'warn', 'timeout', 'untimeout'], note: str, minutes: int = 10):
        if not await self.require_staff(interaction):
            return
        if not 5 <= len(note.strip()) <= 1800:
            return await interaction.response.send_message('Notes must contain 5–1800 characters.', ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        case = await store.get_case(interaction.guild_id, case_id)
        if not case:
            return await interaction.followup.send('Case not found in this server.', ephemeral=True)
        if action != 'note':
            member = interaction.guild.get_member(case['target_id'])
            me = interaction.guild.me
            if not member or member.id == interaction.user.id or member.id == interaction.guild.owner_id or member.bot:
                return await interaction.followup.send('That member cannot receive this action.', ephemeral=True)
            if (interaction.user.id != interaction.guild.owner_id and member.top_role >= interaction.user.top_role) or member.top_role >= me.top_role:
                return await interaction.followup.send('The member is above you or the bot in the role hierarchy.', ephemeral=True)
            try:
                if action == 'warn':
                    await member.send(f'Warning in {interaction.guild.name}, case #{case_id}: {note[:1500]}\nYou may appeal once the case is resolved using /appeal in that server.', allowed_mentions=NO_MENTIONS)
                else:
                    if not me.guild_permissions.moderate_members or member.guild_permissions.administrator:
                        return await interaction.followup.send('The bot cannot timeout that member.', ephemeral=True)
                    if action == 'timeout' and not 1 <= minutes <= 40320:
                        return await interaction.followup.send('Timeout must be between 1 and 40320 minutes.', ephemeral=True)
                    await member.timeout(timedelta(minutes=minutes) if action == 'timeout' else None,
                                         reason=f'Case #{case_id}, moderator {interaction.user.id}: {note[:350]}')
            except discord.HTTPException as error:
                await store.record_action(interaction.guild_id, case_id, interaction.user.id, f'{action}_failed', type(error).__name__)
                return await interaction.followup.send('Discord refused the action; the failure was recorded. Check permissions or whether DMs are closed.', ephemeral=True)
        await store.record_action(interaction.guild_id, case_id, interaction.user.id, action, note.strip())
        await interaction.followup.send('Action recorded for this server’s case.', ephemeral=True)

    @commands.hybrid_command(name='communitysecurity', description='Configure local flood detection and raid alerts.')
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def communitysecurity(self, ctx, enabled: bool, channel: discord.TextChannel,
                                messages: int = 8, mentions: int = 10, window: int = 10,
                                joins: int = 8, join_window: int = 20,
                                action: Literal['alert', 'delete'] = 'alert', share_signals: bool = False):
        if channel.guild.id != ctx.guild.id or not channel.permissions_for(ctx.author).view_channel or not channel.permissions_for(ctx.guild.me).send_messages:
            return await ctx.send('Choose an accessible channel in this server where the bot can send alerts.', ephemeral=True)
        if not (3 <= messages <= 100 and 3 <= mentions <= 100 and 3 <= joins <= 100 and 3 <= window <= 120 and 5 <= join_window <= 300):
            return await ctx.send('Thresholds: 3–100 messages/mentions/joins; window 3–120 seconds; join window 5–300 seconds.', ephemeral=True)
        if action == 'delete' and not ctx.guild.me.guild_permissions.manage_messages:
            return await ctx.send('Delete mode needs the bot’s Manage Messages permission.', ephemeral=True)
        await store.configure_security(ctx.guild.id, enabled, channel.id, messages, mentions, window, joins, join_window, action, share_signals)
        self.settings = await store.security_settings()
        await ctx.send(f"Local security {'enabled' if enabled else 'disabled'} ({action}). Raid detection sends alerts. "
                       + ('Anonymous signals may go to explicitly trusting servers with network protection enabled.' if share_signals else 'Network signal sharing is off.'), ephemeral=True)

    def queue_alert(self, payload):
        try:
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            log.warning('Community security queue full; a safety alert was dropped')

    @commands.Cog.listener()
    async def on_message(self, message):
        if not message.guild or message.author.bot or (isinstance(message.author, discord.Member) and message.author.guild_permissions.manage_messages):
            return
        cfg = self.settings.get(message.guild.id)
        if not cfg or not cfg['enabled']:
            return
        mention_count = len(message.raw_mentions) + len(message.raw_role_mentions) + (int(message.mention_everyone) * cfg['mention_limit'])
        over, alert = self.flood.check((message.guild.id, message.author.id), time.monotonic(), cfg['window_seconds'], cfg['message_limit'], cfg['mention_limit'], mention_count)
        if alert or (over and cfg['action'] == 'delete'):
            self.queue_alert((message.guild.id, message if cfg['action'] == 'delete' and over else None,
                              f'Message/mention flood threshold for user {message.author.id} in channel {message.channel.id}. Review context before acting.' if alert else None,
                              'Message/mention flood threshold detected; local moderators should review context.' if alert else None))

    @commands.Cog.listener()
    async def on_member_join(self, member):
        cfg = self.settings.get(member.guild.id)
        if not cfg or not cfg['enabled']:
            return
        _, alert = self.joins.check(member.guild.id, time.monotonic(), cfg['join_window_seconds'], cfg['join_limit'], cooldown=120)
        if alert:
            text = f"Join surge: at least {cfg['join_limit']} joins within {cfg['join_window_seconds']} seconds. Review invites and verification settings; no automatic punishment applied."
            self.queue_alert((member.guild.id, None, text, text))

    @commands.Cog.listener()
    async def on_member_remove(self, member):
        await store.remove_member(member.guild.id, member.id)

    async def alert_worker(self):
        await self.bot.wait_until_ready()
        while True:
            guild_id, message, text, signal = await self.queue.get()
            try:
                cfg = self.settings.get(guild_id)
                guild = self.bot.get_guild(guild_id)
                if not cfg or not cfg['enabled'] or not guild:
                    continue
                if message and cfg['action'] == 'delete':
                    try:
                        await message.delete()
                    except discord.HTTPException:
                        pass
                channel = guild.get_channel(cfg['alert_channel_id'])
                if text and channel:
                    try:
                        await channel.send(text, allowed_mentions=NO_MENTIONS)
                    except discord.HTTPException:
                        log.warning('Local security notification failed for guild %s', guild_id)
                guardian = self.bot.get_cog('Guardian')
                if signal and cfg['share_signals'] and guardian:
                    await guardian.publish_security_alert(guild_id, signal, source='community')
            except Exception as error:
                log.warning('Community alert failed: %s', type(error).__name__)
            finally:
                self.queue.task_done()

    @commands.hybrid_command(name='event', description='Create a shared event; members voluntarily subscribe to reminders.')
    @commands.guild_only()
    @commands.cooldown(2, 60, commands.BucketType.member)
    async def event(self, ctx, starts_at: str, *, title: str):
        if not isinstance(ctx.channel, discord.TextChannel):
            return await ctx.send('Create events in a server text channel.', ephemeral=True)
        if not ctx.channel.permissions_for(ctx.author).send_messages or not ctx.channel.permissions_for(ctx.guild.me).send_messages:
            return await ctx.send('You and the bot need Send Messages here.', ephemeral=True)
        if not 1 <= len(title.strip()) <= 150:
            return await ctx.send('Use a title between 1 and 150 characters.', ephemeral=True)
        try:
            when = event_time(starts_at, await db.get_user_timezone(ctx.author.id))
        except (ValueError, pytz.Error):
            return await ctx.send('Use an ISO date/time, e.g. "2026-10-18T18:00" in your saved timezone, or "2026-10-18T18:00+06:00". Choose 30 seconds–366 days ahead; ambiguous DST times need an explicit offset.', ephemeral=True)
        if ctx.interaction:
            await ctx.defer(ephemeral=True)
        event_id = await store.create_event(ctx.guild.id, ctx.author.id, ctx.channel.id, title.strip(), when.isoformat())
        if event_id is None:
            return await ctx.send('Active event limit reached: five per creator or thirty per server.', ephemeral=True)
        view = EventSubscriptionView(self, event_id)
        embed = discord.Embed(title=title.strip(), description=f'Starts <t:{int(when.timestamp())}:F> (<t:{int(when.timestamp())}:R>).\nSubscribe for an optional channel mention. /eventdelivery can opt you into DMs.', color=discord.Color.blue())
        embed.set_footer(text=f'Event #{event_id} · creator {ctx.author.id}')
        try:
            sent = await ctx.channel.send(embed=embed, view=view, allowed_mentions=NO_MENTIONS)
            await store.set_event_message(ctx.guild.id, event_id, sent.id)
        except discord.HTTPException:
            await store.cancel_event(ctx.guild.id, event_id)
            view.stop()
            return await ctx.send('Could not post the event; it was cancelled. Check channel permissions.', ephemeral=True)
        self.views[event_id] = view
        await ctx.send(f'Event #{event_id} created. Nobody is subscribed automatically.', ephemeral=True)

    @commands.hybrid_command(name='events', description='List upcoming events in channels you can access.')
    @commands.guild_only()
    async def events(self, ctx):
        lines = []
        for event in await store.active_events(ctx.guild.id):
            channel = ctx.guild.get_channel(event['channel_id'])
            if channel and channel.permissions_for(ctx.author).view_channel:
                stamp = int(datetime.fromisoformat(event['scheduled_at']).timestamp())
                lines.append(f"#{event['id']} · {discord.utils.escape_markdown(event['title'])} · <t:{stamp}:R>")
        await ctx.send(('\n'.join(lines) or 'No upcoming events in channels you can access.')[:1900], ephemeral=True, allowed_mentions=NO_MENTIONS)

    @commands.hybrid_command(name='eventcancel', description='Cancel your event, or moderate an event in this server.')
    @commands.guild_only()
    async def eventcancel(self, ctx, event_id: int):
        event = await store.get_event(ctx.guild.id, event_id)
        channel = ctx.guild.get_channel(event['channel_id']) if event else None
        if not event or not can_manage_event(ctx.author, event) or (channel and not channel.permissions_for(ctx.author).view_channel):
            return await ctx.send('Event not found, or you are not its creator or a server event manager.', ephemeral=True)
        changed = await store.cancel_event(ctx.guild.id, event_id)
        view = self.views.pop(event_id, None)
        if view:
            view.stop()
        await ctx.send('Event cancelled.' if changed else 'This event has already finished.', ephemeral=True)

    @commands.hybrid_command(name='eventdelivery', description='Choose channel mentions or explicitly opt into event DMs in this server.')
    @commands.guild_only()
    async def eventdelivery(self, ctx, mode: Literal['channel', 'dm']):
        await store.set_dm_preference(ctx.guild.id, ctx.author.id, mode == 'dm')
        await ctx.send('Event preference saved for this server and your upcoming subscriptions: ' +
                       ('DM reminders (you opted in).' if mode == 'dm' else 'channel mentions; event DMs are off.'), ephemeral=True)

    async def deliver_one(self, job):
        event = await store.get_event(job['guild_id'], job['event_id'])
        guild = self.bot.get_guild(job['guild_id'])
        channel = guild.get_channel(job['channel_id']) if guild else None
        if not event or event['state'] != 'dispatching' or not guild or not channel:
            return await store.finish_delivery(job['id'], 'skipped')
        subscriptions = await store.event_subscriptions(guild.id, event['id'])
        if job['user_id']:
            subscribed = next((s for s in subscriptions if s['user_id'] == job['user_id'] and s['dm_opt_in']), None)
            member = guild.get_member(job['user_id'])
            if not subscribed or not member or not channel.permissions_for(member).view_channel:
                return await store.finish_delivery(job['id'], 'skipped')
            await member.send(f"Event starting in {guild.name}: {event['title']}\nhttps://discord.com/channels/{guild.id}/{channel.id}/{event['message_id'] or ''}\nUse /eventdelivery channel in that server to disable future event DMs.", allowed_mentions=NO_MENTIONS)
        else:
            members = [guild.get_member(s['user_id']) for s in subscriptions if not s['dm_opt_in']]
            members = [m for m in members if m and channel.permissions_for(m).view_channel]
            mentions = ' '.join(m.mention for m in members)
            # The title belongs in an embed so all 80 opted-in mentions fit in
            # Discord's 2,000-character content limit without partial retries.
            embed = discord.Embed(title=f"Event starting: {event['title']}", color=discord.Color.blue())
            await channel.send(mentions or None, embed=embed,
                               allowed_mentions=discord.AllowedMentions(users=members, roles=False, everyone=False, replied_user=False))
        await store.finish_delivery(job['id'])

    @tasks.loop(seconds=10)
    async def deliver_events(self):
        try:
            await store.prepare_due_events()
            for pending in await store.due_deliveries():
                job = await store.claim_delivery(pending['id'])
                if not job:
                    continue
                try:
                    await self.deliver_one(job)
                except discord.Forbidden:
                    await store.finish_delivery(job['id'], 'failed', 'Forbidden')
                except discord.NotFound:
                    await store.finish_delivery(job['id'], 'failed', 'NotFound')
                except Exception as error:
                    await store.retry_delivery(job, type(error).__name__)
            await store.finalize_events()
            for event_id, view in list(self.views.items()):
                event = await db._one('SELECT state FROM community_events WHERE id=?', (event_id,))
                if not event or event['state'] != 'scheduled':
                    view.stop()
                    self.views.pop(event_id, None)
            self.last_delivery_error = None
        except Exception as error:
            self.last_delivery_error = type(error).__name__
            log.warning('Event delivery loop failed: %s', self.last_delivery_error)

    @deliver_events.before_loop
    async def before_delivery(self):
        await self.bot.wait_until_ready()

    @commands.hybrid_command(name='health', description='Check storage, local permissions and background work.')
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    @commands.cooldown(1, 30, commands.BucketType.guild)
    async def health(self, ctx):
        if ctx.interaction:
            await ctx.defer(ephemeral=True)
        started = time.monotonic()
        privacy_settings = None
        try:
            await db._one('SELECT 1 AS ok')
            storage = f'OK ({(time.monotonic() - started) * 1000:.0f} ms)'
            pending = await db._one("SELECT COUNT(*) AS n FROM community_event_delivery WHERE guild_id=? AND state IN ('pending','sending')", (ctx.guild.id,))
            failures = await db._one("SELECT COUNT(*) AS n FROM community_event_delivery WHERE guild_id=? AND state='failed'", (ctx.guild.id,))
            events = f"{pending['n']} pending; {failures['n']} failed deliveries in this server"
            privacy_settings = await db.get_privacy(ctx.guild.id)
        except Exception as error:
            storage, events = type(error).__name__, 'Unavailable'
        perms = ctx.channel.permissions_for(ctx.guild.me)
        missing = [name.replace('_', ' ') for name in ('view_channel', 'send_messages', 'embed_links', 'read_message_history', 'manage_messages') if not getattr(perms, name)]
        embed = discord.Embed(title='Bot health', color=discord.Color.green())
        embed.add_field(name='Storage', value=storage)
        embed.add_field(name='Missing permissions here', value=', '.join(missing) or 'None')
        embed.add_field(name='Events', value=events, inline=False)
        embed.add_field(name='Event worker', value=('Running' if self.deliver_events.is_running() else 'Stopped') + (f'; last error: {self.last_delivery_error}' if self.last_delivery_error else ''))
        embed.add_field(name='Security worker', value='Running' if self.worker and not self.worker.done() else 'Stopped')
        alarm_worker = getattr(self.bot, 'alarm_worker', None)
        embed.add_field(name='Alarm scheduler', value='Running' if alarm_worker and alarm_worker.is_running() else 'Stopped')
        guardian = self.bot.get_cog('Guardian')
        if guardian:
            live_workers = sum(not task.done() for task in guardian.media_workers)
            embed.add_field(name='Guardian workers', value=f"Protection: {'running' if guardian.enforce_loop.is_running() else 'stopped'}; media: {live_workers}/{len(guardian.media_workers)}")
        embed.add_field(name='Community alert queue', value=f'{self.queue.qsize()}/{self.queue.maxsize}')
        if privacy_settings:
            embed.add_field(name='This server’s privacy', value=f"Routine archive: {'on' if privacy_settings['archive_enabled'] else 'off'}; retention: {privacy_settings['retention_days']} days")
        privacy = self.bot.get_cog('Privacy')
        if privacy:
            backup = getattr(privacy, 'last_backup_at', None)
            embed.add_field(name='Backup', value=str(backup or 'No successful automatic backup this session'))
            embed.add_field(name='Backup / retention errors', value=f"{getattr(privacy, 'last_backup_error', None) or 'None'} / {getattr(privacy, 'last_retention_error', None) or 'None'}")
        embed.set_footer(text='Delivery is retried after temporary failures; a crash after Discord accepts a message can cause a duplicate.')
        await ctx.send(embed=embed, ephemeral=True, allowed_mentions=NO_MENTIONS)


async def setup(bot):
    await bot.add_cog(Community(bot))
