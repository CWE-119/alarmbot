import os
os.environ['BOT_TESTING'] = '1'

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest
import pytest_asyncio

import community
import community_store as store
import database as db


@pytest_asyncio.fixture
async def storage(tmp_path, monkeypatch):
    await db.close_db()
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'community.db'))
    await db.init_db()
    await store.init_db()
    yield
    await db.close_db()


def future():
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


@pytest.mark.asyncio
async def test_cases_and_actions_cannot_cross_servers(storage):
    case_id = await store.create_case(10, 1, 2, 'Private report', 'Private evidence')
    assert await store.get_case(20, case_id) is None
    assert await store.list_cases(20) == []
    assert not await store.resolve_case(20, case_id, 3, 'Wrong server')
    await store.record_action(20, case_id, 3, 'note', 'Foreign action')
    assert await store.case_actions(10, case_id) == []
    await store.record_action(10, case_id, 3, 'note', 'Local action')
    assert len(await store.case_actions(10, case_id)) == 1
    assert await store.case_actions(20, case_id) == []


@pytest.mark.asyncio
async def test_appeals_require_participation_and_different_reviewer(storage):
    case_id = await store.create_case(10, 1, 2, 'Report reason')
    assert await store.resolve_case(10, case_id, 3, 'Initial resolution')
    assert not await store.appeal_case(20, case_id, 1, 'Wrong server')
    assert not await store.appeal_case(10, case_id, 99, 'Unrelated person')
    assert await store.appeal_case(10, case_id, 2, 'Please reconsider')
    assert not await store.resolve_case(10, case_id, 3, 'Same reviewer')
    assert await store.resolve_case(10, case_id, 4, 'Independent review')
    assert [a['action'] for a in await store.case_actions(10, case_id)] == ['resolve', 'appeal', 'resolve']


@pytest.mark.asyncio
async def test_retention_preserves_other_server_and_active_cases(storage):
    case_ids = {}
    event_ids = {}
    for gid in (10, 20):
        case_ids[gid] = await store.create_case(gid, 1, 2, 'Resolved reason')
        await store.resolve_case(gid, case_ids[gid], 3, 'Resolved locally')
        await store.create_case(gid, 1, 2, 'Open investigation')
        event_ids[gid] = await store.create_event(gid, 1, 100*gid, 'Past event', future())
        await store.subscribe(gid, event_ids[gid], 2)
        await store.cancel_event(gid, event_ids[gid])
    await db._run("UPDATE community_cases SET created_at='2020-01-01T00:00:00+00:00'")
    await db._run("UPDATE community_events SET scheduled_at='2020-01-01T00:00:00+00:00'")
    await store.prune(30, guild_id=10)
    assert await store.get_case(10, case_ids[10]) is None
    assert await store.get_case(20, case_ids[20]) is not None
    assert len(await store.list_cases(10)) == 1
    assert await store.case_actions(10, case_ids[10]) == []
    assert len(await store.case_actions(20, case_ids[20])) == 1
    assert await store.get_event(10, event_ids[10]) is None
    assert await store.get_event(20, event_ids[20]) is not None
    assert await store.event_subscriptions(10, event_ids[10]) == []
    assert len(await store.event_subscriptions(20, event_ids[20])) == 1


@pytest.mark.asyncio
async def test_events_preferences_and_cancel_are_scoped(storage):
    first = await store.create_event(10, 1, 100, 'First server', future())
    second = await store.create_event(20, 1, 200, 'Second server', future())
    assert await store.subscribe(20, first, 1) is None
    await store.set_dm_preference(10, 1, True)
    assert await store.subscribe(10, first, 1) is True
    assert await store.subscribe(20, second, 1) is False
    await store.unsubscribe(20, first, 1)
    assert len(await store.event_subscriptions(10, first)) == 1
    assert not await store.cancel_event(20, first)
    await store.remove_member(10, 1)
    assert await store.event_subscriptions(10, first) == []
    assert len(await store.event_subscriptions(20, second)) == 1


@pytest.mark.asyncio
async def test_event_limits_are_atomic(storage):
    results = await asyncio.gather(*(store.create_event(10, 1, 100, 'An event', future()) for _ in range(8)))
    assert len([eid for eid in results if eid is not None]) == 5
    assert await store.create_event(20, 1, 200, 'Independent quota', future()) is not None


@pytest.mark.asyncio
async def test_event_subscription_limit_is_bounded(storage):
    event_id = await store.create_event(10, 1, 100, 'Busy event', future())
    for uid in range(1, 81):
        assert await store.subscribe(10, event_id, uid) is False
    assert await store.subscribe(10, event_id, 81) is None
    assert await store.subscribe(10, event_id, 1) is False


@pytest.mark.asyncio
async def test_event_delivery_is_claimed_once_retries_and_finishes(storage):
    event_id = await store.create_event(10, 1, 100, 'Event', '2020-01-01T00:00:00+00:00')
    await store.prepare_due_events()
    await store.prepare_due_events()
    pending = await store.due_deliveries()
    assert len(pending) == 1
    claims = await asyncio.gather(*(store.claim_delivery(pending[0]['id']) for _ in range(2)))
    jobs = [job for job in claims if job]
    assert len(jobs) == 1
    assert jobs[0]['attempts'] == 1
    await store.retry_delivery(jobs[0], 'TimeoutError')
    assert await store.due_deliveries() == []
    job = await store.claim_delivery(pending[0]['id'], now='2099-01-01T00:00:00+00:00')
    assert job['attempts'] == 2
    await store.finish_delivery(job['id'])
    await store.finalize_events()
    assert (await store.get_event(10, event_id))['state'] == 'completed'


@pytest.mark.asyncio
async def test_delivery_crash_lease_recovery_and_cancellation(storage):
    event_id = await store.create_event(10, 1, 100, 'Event', '2020-01-01T00:00:00+00:00')
    await store.prepare_due_events()
    job = await store.claim_delivery((await store.due_deliveries())[0]['id'])
    assert await store.claim_delivery(job['id']) is None
    recovered = await store.claim_delivery(job['id'], now='2099-01-01T00:00:00+00:00')
    assert recovered['attempts'] == 2
    await store.cancel_event(10, event_id)
    await store.finish_delivery(job['id'])
    assert (await store.get_event(10, event_id))['state'] == 'cancelled'
    assert (await db._one('SELECT state FROM community_event_delivery WHERE id=?', (job['id'],)))['state'] == 'cancelled'


@pytest.mark.asyncio
async def test_event_retry_exhaustion_is_visible_as_failure(storage):
    event_id = await store.create_event(10, 1, 100, 'Event', '2020-01-01T00:00:00+00:00')
    await store.prepare_due_events()
    delivery_id = (await store.due_deliveries())[0]['id']
    for attempt in range(1, 6):
        job = await store.claim_delivery(delivery_id, now='2099-01-01T00:00:00+00:00')
        assert job['attempts'] == attempt
        await store.retry_delivery(job, 'TimeoutError')
    await store.finalize_events()
    assert (await store.get_event(10, event_id))['state'] == 'failed'
    assert await store.claim_delivery(delivery_id, now='2099-01-01T00:00:00+00:00') is None


@pytest.mark.asyncio
async def test_dm_optout_and_unsubscribe_skip_pending_deliveries(storage):
    event_id = await store.create_event(10, 1, 100, 'Event', '2020-01-01T00:00:00+00:00')
    await store.set_dm_preference(10, 2, True)
    await store.subscribe(10, event_id, 2)
    await store.prepare_due_events()
    job = next(j for j in await store.due_deliveries() if j['user_id'] == 2)
    job = await store.claim_delivery(job['id'])
    await store.set_dm_preference(10, 2, False)
    member = SimpleNamespace(send=AsyncMock())
    channel = SimpleNamespace(id=100, permissions_for=lambda _: SimpleNamespace(view_channel=True))
    guild = SimpleNamespace(id=10, get_channel=lambda _: channel, get_member=lambda _: member)
    cog = community.Community(MagicMock(get_guild=lambda _: guild))
    await cog.deliver_one(job)
    member.send.assert_not_called()
    assert (await db._one('SELECT state FROM community_event_delivery WHERE id=?', (job['id'],)))['state'] == 'skipped'


@pytest.mark.asyncio
async def test_channel_event_mentions_only_subscribers_with_access(storage):
    event_id = await store.create_event(10, 1, 100, '@everyone ' + '*'*130, '2020-01-01T00:00:00+00:00')
    members = {}
    for index in range(80):
        uid = 9000000000000000000 + index
        await store.subscribe(10, event_id, uid)
        members[uid] = SimpleNamespace(id=uid, mention=f'<@{uid}>')
    denied = next(iter(members))
    channel = SimpleNamespace(id=100, send=AsyncMock(), permissions_for=lambda member: SimpleNamespace(view_channel=member.id != denied))
    guild = SimpleNamespace(id=10, get_channel=lambda _: channel, get_member=members.get)
    cog = community.Community(MagicMock(get_guild=lambda _: guild))
    await store.prepare_due_events()
    job = await store.claim_delivery((await store.due_deliveries())[0]['id'])
    await cog.deliver_one(job)
    args, kwargs = channel.send.call_args
    assert len(args[0]) <= 2000
    assert str(denied) not in args[0]
    assert kwargs['allowed_mentions'].everyone is False
    assert kwargs['allowed_mentions'].roles is False
    assert {m.id for m in kwargs['allowed_mentions'].users} == set(members) - {denied}


@pytest.mark.asyncio
async def test_case_notification_copies_no_evidence(storage):
    await store.set_report_channel(10, 100)
    channel = SimpleNamespace(send=AsyncMock())
    guild = SimpleNamespace(id=10, get_channel=lambda _: channel)
    cog = community.Community(MagicMock())
    await cog.notify_case(guild, 123)
    message = channel.send.call_args.args[0]
    assert message == 'New report: case #123. Staff can privately review it with /case.'


@pytest.mark.asyncio
async def test_staff_check_cannot_use_bot_owner_bypass():
    owner = MagicMock(spec=discord.Member)
    owner.guild_permissions.moderate_members = False
    interaction = SimpleNamespace(guild=object(), user=owner, response=SimpleNamespace(send_message=AsyncMock()))
    bot = MagicMock(is_owner=AsyncMock(return_value=True))
    cog = community.Community(bot)
    assert not await cog.require_staff(interaction)
    bot.is_owner.assert_not_called()


@pytest.mark.asyncio
async def test_shared_security_alert_uses_guardian_trust_gate_only():
    guardian = SimpleNamespace(publish_security_alert=AsyncMock())
    channel = SimpleNamespace(send=AsyncMock())
    guild = SimpleNamespace(get_channel=lambda _: channel)
    bot = SimpleNamespace(wait_until_ready=AsyncMock(), get_guild=lambda _: guild,
                          get_cog=lambda name: guardian if name == 'Guardian' else None)
    cog = community.Community(bot)
    cog.settings[10] = {'enabled': 1, 'action': 'alert', 'alert_channel_id': 100, 'share_signals': 1}
    cog.queue_alert((10, None, 'Local message for staff', 'Anonymous flood signal'))
    worker = asyncio.create_task(cog.alert_worker())
    await asyncio.wait_for(cog.queue.join(), timeout=2)
    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)
    guardian.publish_security_alert.assert_awaited_once_with(10, 'Anonymous flood signal', source='community')
    channel.send.assert_awaited_once()


def test_event_management_requires_current_server():
    member = MagicMock(spec=discord.Member)
    member.id = 1
    member.guild.id = 20
    member.guild_permissions.manage_guild = True
    event = {'guild_id': 10, 'creator_id': 1}
    assert not community.can_manage_event(member, event)
    member.guild.id = 10
    assert community.can_manage_event(member, event)


def test_flood_windows_are_scoped_bounded_and_have_cooldowns():
    window = community.FloodWindow(capacity=2, max_samples=3)
    assert window.check((10, 1), 0, 10, 2) == (False, False)
    assert window.check((20, 1), 1, 10, 2) == (False, False)
    assert window.check((10, 1), 2, 10, 2) == (True, True)
    assert window.check((10, 1), 3, 10, 2) == (True, False)
    assert window.check((10, 1), 20, 10, 2) == (False, False)
    window.check((30, 1), 21, 10, 2)
    assert len(window.entries) == 2
    for tick in range(22, 30):
        window.check((30, 1), tick, 100, 2)
    assert len(window.entries[(30, 1)][0]) == 3


def test_event_timezone_parsing_rejects_ambiguous_local_times():
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    import pytz
    with pytest.raises(pytz.AmbiguousTimeError):
        community.event_time('2026-11-01T01:30', 'America/New_York', now)
    assert community.event_time('2026-11-01T01:30-04:00', 'America/New_York', now).hour == 5
