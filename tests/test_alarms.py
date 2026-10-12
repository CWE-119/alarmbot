"""Offline regression coverage for ownership, calendar rules and delivery recovery."""
import os
os.environ['BOT_TESTING'] = '1'

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import discord
import pytest
import pytest_asyncio

import alarm_store as alarms
import database as db
import main
import scheduling as schedule

UTC = timezone.utc
NOW = datetime(2030, 1, 1, 12, tzinfo=UTC)


@pytest_asyncio.fixture
async def storage(tmp_path, monkeypatch):
    await db.close_db()
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'alarms.db'))
    monkeypatch.setattr(alarms, 'utcnow', lambda: NOW)
    monkeypatch.setattr(main, 'utcnow', lambda: NOW)
    await db.init_db()
    await alarms.init_db()
    yield
    await db.close_db()


async def add(*, user=1, guild=10, when=NOW, repeat=None, until=None):
    return await alarms.add(user, guild, 100, 'channel', when, 'UTC', repeat, 'Reminder', until)


@pytest.mark.parametrize(('repeat', 'expected'), [
    ('daily', datetime(2030, 1, 2, 12, tzinfo=UTC)),
    ('weekly', datetime(2030, 1, 8, 12, tzinfo=UTC)),
    ('weekdays', datetime(2030, 1, 2, 12, tzinfo=UTC)),
    ('mon,fri', datetime(2030, 1, 4, 12, tzinfo=UTC)),
])
def test_calendar_recurrence(repeat, expected):
    assert schedule.next_occurrence('2030-01-01T12:00:00', 'UTC', repeat, NOW) == expected


def test_monthly_short_month_does_not_drift():
    anchor = '2030-01-31T09:00:00'
    feb = schedule.next_occurrence(anchor, 'UTC', 'monthly', datetime(2030, 1, 31, 9, tzinfo=UTC))
    march = schedule.next_occurrence(anchor, 'UTC', 'monthly', feb)
    assert feb == datetime(2030, 2, 28, 9, tzinfo=UTC)
    assert march == datetime(2030, 3, 31, 9, tzinfo=UTC)


def test_dst_gap_advances_one_occurrence_without_changing_anchor():
    anchor = '2026-03-07T02:30:00'
    gap = schedule.next_occurrence(anchor, 'America/New_York', 'daily', datetime(2026, 3, 7, 8, tzinfo=UTC))
    following = schedule.next_occurrence(anchor, 'America/New_York', 'daily', gap)
    assert gap == datetime(2026, 3, 8, 7, 30, tzinfo=UTC)
    assert following == datetime(2026, 3, 9, 6, 30, tzinfo=UTC)


def test_dst_fold_uses_first_occurrence_only():
    first = schedule.next_occurrence('2026-10-31T01:30:00', 'America/New_York', 'daily', datetime(2026, 11, 1, tzinfo=UTC))
    assert first == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
    assert schedule.next_occurrence('2026-10-31T01:30:00', 'America/New_York', 'daily', first) == datetime(2026, 11, 2, 6, 30, tzinfo=UTC)


def test_quiet_hours_second_fold_never_defers_into_past():
    now = datetime(2026, 11, 1, 6, 15, tzinfo=UTC)
    assert schedule.quiet_end(now, 'America/New_York', '22:00', '01:30') == datetime(2026, 11, 1, 6, 30, tzinfo=UTC)


def test_parser_preserves_message_and_explicit_repeat_off():
    when, repeat, message = schedule.parse_alarm_args('tomorrow 9am repeat off | daily report', UTC, NOW)
    assert when == datetime(2030, 1, 2, 9, tzinfo=UTC)
    assert repeat == 'once'
    assert message == 'daily report'
    assert schedule.parse_when('2029-12-31 9am', UTC, NOW) is None
    assert schedule.parse_when('in 2h', UTC, NOW) == NOW + timedelta(hours=2)


async def test_server_and_owner_scope_with_private_self_management(storage):
    first = await add(guild=10)
    other = await add(guild=20)
    await add(user=2, guild=10)
    assert await alarms.get(other['id'], 1, 10) is None
    assert await alarms.get(first['id'], 2, None) is None
    assert [a['id'] for a in (await alarms.list_for(1, 10))[0]] == [first['id']]
    assert (await alarms.list_for(1, None))[1] == 2
    await alarms.record(other, 'delivered')
    assert await alarms.history(1, 10) == []
    assert len(await alarms.history(1, None)) == 1


async def test_legacy_unknown_scope_hidden_from_all_guilds(storage):
    alarm = await add()
    await alarms.mutate(alarm, {'scope_known': 0})
    assert await alarms.get(alarm['id'], 1, 10) is None
    assert await alarms.get(alarm['id'], 1, None) is not None


async def test_delivery_retry_is_persisted_and_one_time_alarm_retained(storage):
    alarm = await alarms.claim(await add(), NOW)
    assert not await alarms.failed(alarm, 'temporary outage', now=NOW)
    retry = await alarms.get(alarm['id'])
    assert retry['state'] == 'active'
    assert retry['attempts'] == 1
    assert await alarms.due(NOW + timedelta(seconds=29)) == []
    await db.close_db()
    recovered = (await alarms.due(NOW + timedelta(seconds=30)))[0]
    claimed = await alarms.claim(recovered, NOW + timedelta(seconds=30))
    assert await alarms.delivered(claimed, NOW + timedelta(seconds=30))
    assert (await alarms.get(alarm['id']))['state'] == 'delivered'
    assert [r['outcome'] for r in await alarms.history(1, 10)] == ['delivered', 'retry']


async def test_retry_exhaustion_stops_without_deleting_alarm(storage):
    alarm = await add()
    now = NOW
    for attempt in range(alarms.MAX_ATTEMPTS):
        alarm = await alarms.claim(alarm, now)
        assert await alarms.failed(alarm, 'offline', now=now) == (attempt == alarms.MAX_ATTEMPTS - 1)
        alarm = await alarms.get(alarm['id'])
        if alarm['next_attempt_utc']:
            now = schedule.as_utc(alarm['next_attempt_utc'])
    assert alarm['state'] == 'failed'
    assert await alarms.due(now + timedelta(days=1)) == []


async def test_downtime_sends_one_catchup_then_next_future_occurrence(storage):
    alarm = await add(when=NOW-timedelta(days=100), repeat='daily')
    claimed = await alarms.claim(alarm, NOW)
    await alarms.delivered(claimed, NOW)
    alarm = await alarms.get(alarm['id'])
    assert schedule.as_utc(alarm['time_utc']) == NOW + timedelta(days=1)
    assert await alarms.due(NOW + timedelta(seconds=10)) == []


async def test_snooze_keeps_recurring_anchor(storage):
    alarm = await add(repeat='daily')
    anchor = alarm['schedule_anchor']
    alarm = await alarms.snooze(alarm, timedelta(minutes=10))
    assert alarm['schedule_anchor'] == anchor
    assert await alarms.due(NOW) == []
    claimed = await alarms.claim(alarm, NOW + timedelta(minutes=10))
    await alarms.delivered(claimed, NOW + timedelta(minutes=10))
    alarm = await alarms.get(alarm['id'])
    assert alarm['schedule_anchor'] == anchor
    assert schedule.as_utc(alarm['time_utc']) == NOW + timedelta(days=1)


async def test_stale_worker_cannot_claim_deferred_or_edited_alarm(storage):
    alarm = await add()
    claimed = await alarms.claim(alarm, NOW)
    await alarms.defer(claimed, NOW + timedelta(hours=1))
    assert await alarms.claim(alarm, NOW) is None
    changed = await alarms.mutate(await alarms.get(alarm['id']), {'message': 'changed'})
    assert await alarms.claim(alarm, NOW + timedelta(hours=1)) is None
    assert await alarms.claim(changed, NOW + timedelta(hours=1)) is not None


async def test_lease_expires_and_stale_completion_cannot_override_recovery(storage):
    alarm = await add()
    first = await alarms.claim(alarm, NOW)
    assert await alarms.claim(alarm, NOW + timedelta(minutes=4)) is None
    recovered = await alarms.claim(alarm, NOW + timedelta(minutes=5))
    assert recovered['lease_token'] != first['lease_token']
    assert not await alarms.delivered(first, NOW)
    assert await alarms.delivered(recovered, NOW)


async def test_active_alarm_limit_rejects_insert_without_returning_previous_alarm(storage, monkeypatch):
    monkeypatch.setattr(alarms, 'MAX_ACTIVE', 1)
    await add()
    with pytest.raises(ValueError, match='active reminders'):
        await add(guild=20)
    assert (await alarms.list_for(1, None))[1] == 1


async def test_end_date_stops_recurring_schedule(storage):
    alarm = await add(repeat='daily', until=NOW + timedelta(hours=1))
    await alarms.delivered(await alarms.claim(alarm, NOW), NOW)
    assert (await alarms.get(alarm['id']))['state'] == 'delivered'


async def test_delivery_allows_only_reminder_owner_mentions(storage, monkeypatch):
    alarm = await add()
    alarm = await alarms.mutate(alarm, {'message': '@everyone <@2> <@&3>'})
    channel = SimpleNamespace(send=AsyncMock())
    monkeypatch.setattr(main, 'destination_for', AsyncMock(return_value=channel))
    await main.deliver_one(alarm)
    allowed = channel.send.call_args.kwargs['allowed_mentions'].to_dict()
    assert allowed['users'] == [1]
    assert 'everyone' not in allowed['parse']
    assert 'roles' not in allowed['parse']
    assert (await alarms.get(alarm['id']))['state'] == 'delivered'


async def test_edit_during_destination_lookup_cancels_pending_send(storage, monkeypatch):
    alarm = await add()
    channel = SimpleNamespace(send=AsyncMock())
    async def lookup(*args):
        await alarms.mutate(await alarms.get(alarm['id']), {'paused': 1})
        return channel
    monkeypatch.setattr(main, 'destination_for', lookup)
    await main.deliver_one(alarm)
    channel.send.assert_not_awaited()
    assert (await alarms.get(alarm['id']))['paused'] == 1


async def test_permanent_delivery_failure_retains_alarm_and_notifies_owner(storage, monkeypatch):
    alarm = await add()
    monkeypatch.setattr(main, 'destination_for', AsyncMock(side_effect=main.DestinationError('missing channel')))
    notify = AsyncMock()
    monkeypatch.setattr(main, 'notify_failed', notify)
    await main.deliver_one(alarm)
    assert (await alarms.get(alarm['id']))['state'] == 'failed'
    notify.assert_awaited_once()


async def test_destination_rejects_foreign_guild_before_permissions(monkeypatch):
    guild = SimpleNamespace(fetch_member=AsyncMock(return_value=SimpleNamespace(id=1)))
    foreign_channel = SimpleNamespace(guild=SimpleNamespace(id=20))
    monkeypatch.setattr(main.bot, 'get_guild', lambda _: guild)
    monkeypatch.setattr(main.bot, 'get_channel', lambda _: foreign_channel)
    with pytest.raises(main.DestinationError, match='this server'):
        await main.destination_for(1, 10, 'channel', 200)


async def test_destination_rechecks_member_channel_permissions(monkeypatch):
    member, me = SimpleNamespace(id=1), SimpleNamespace(id=2)
    guild = SimpleNamespace(fetch_member=AsyncMock(return_value=member), me=me)
    channel = Mock(spec=discord.TextChannel)
    channel.guild = guild
    channel.permissions_for.side_effect = lambda person: discord.Permissions(view_channel=True, send_messages=person is me)
    monkeypatch.setattr(main.bot, 'get_guild', lambda _: guild)
    monkeypatch.setattr(main.bot, 'get_channel', lambda _: channel)
    with pytest.raises(main.DestinationError, match='You need permission'):
        await main.destination_for(1, 10, 'channel', 200)


async def test_private_thread_parent_permissions_do_not_grant_membership(monkeypatch):
    member, me = SimpleNamespace(id=1), SimpleNamespace(id=2)
    guild = SimpleNamespace(fetch_member=AsyncMock(return_value=member), me=me)
    channel = Mock(spec=discord.Thread)
    channel.guild = guild
    channel.is_private.return_value = True
    channel.permissions_for.return_value = discord.Permissions(view_channel=True, send_messages_in_threads=True)
    channel.fetch_member = AsyncMock(side_effect=discord.NotFound(SimpleNamespace(status=404, reason='Not Found'), 'Unknown member'))
    monkeypatch.setattr(main.bot, 'get_guild', lambda _: guild)
    monkeypatch.setattr(main.bot, 'get_channel', lambda _: channel)
    with pytest.raises(main.DestinationError, match='private thread'):
        await main.destination_for(1, 10, 'channel', 200)


async def test_private_repair_recovers_orphaned_guild_alarm(storage, monkeypatch):
    alarm = await add()
    ctx = SimpleNamespace(author=SimpleNamespace(id=1), guild=None, channel=SimpleNamespace(id=999), interaction=None)
    lookup = AsyncMock(return_value=SimpleNamespace(id=999))
    monkeypatch.setattr(main, 'destination_for', lookup)
    monkeypatch.setattr(main, 'reply', AsyncMock())
    await main.destination_core(ctx, alarm['id'], 'dm')
    lookup.assert_awaited_once_with(1, None, 'dm', None)
    updated = await alarms.get(alarm['id'], 1, None)
    assert updated['guild_id'] is None
    assert updated['destination'] == 'dm'


def test_slash_prefix_and_persistent_buttons_registered():
    assert {'create', 'edit', 'list', 'snooze', 'done', 'destination', 'quiet', 'history', 'status'} <= {c.name for c in main.alarm_group.commands}
    assert all(main.bot.get_command(name) for name in ('setalarm', 'dmalarm', 'snooze', 'editalarm', 'alarmstatus'))
    assert main.ReminderButton(123, 'snooze').item.custom_id == 'alarm:snooze:123'
