import asyncio
import hashlib
import os
import time
from datetime import timedelta
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

os.environ["BOT_TESTING"] = "1"

import pytest
import pytest_asyncio

import database as db
import guardian_store as store
from guardian import Guardian, MEDIA_QUEUE_SIZE, now_utc, text_hash, urls_of


@pytest_asyncio.fixture
async def storage(tmp_path, monkeypatch):
    await db.close_db()
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "guardian.db"))
    await db.init_db()
    await store.init()
    yield
    await db.close_db()


def make_guild(gid=10, uid=7, timeout=None):
    member = NS(id=uid, top_role=1, bot=False, timed_out_until=timeout,
                guild_permissions=NS(administrator=False), mention=f"<@{uid}>")

    async def set_timeout(until, **kwargs):
        member.timed_out_until = until

    member.timeout = AsyncMock(side_effect=set_timeout)
    guild = NS(id=gid, owner_id=99, me=NS(top_role=10,
        guild_permissions=NS(moderate_members=True)))
    guild.get_member = lambda user_id: member if user_id == uid else None
    guild.fetch_member = AsyncMock(return_value=member)
    member.guild = guild
    return guild, member


def make_guardian(guilds=()):
    return Guardian(NS(guilds=list(guilds), get_channel=lambda _: None,
                       get_guild=lambda gid: next((g for g in guilds if g.id == gid), None)))


def flag(source=10, uid=7, expires=None):
    return {"source_guild_id": source, "user_id": uid, "reason": "confirmed scam",
            "expires_at_utc": expires.isoformat() if expires else None}


def test_security_requires_receiving_server_enablement_and_explicit_trust():
    cog = make_guardian()
    assert cog.can_receive_security(10, 10)
    assert not cog.can_receive_security(10, 20)
    cog.trusted_sources.add((20, 10))
    assert not cog.can_receive_security(10, 20)
    cog.network_enabled.add(20)
    assert cog.can_receive_security(10, 20)
    assert not cog.can_receive_security(20, 10)
    assert not cog.can_receive_security(30, 20)


def test_flags_and_local_exemptions_are_source_and_server_scoped():
    cog = make_guardian()
    cog.flagged = {(10, 7): flag(), (30, 7): flag(30)}
    cog.network_enabled.update((20, 40))
    cog.trusted_sources.update(((20, 10), (20, 30), (40, 10)))
    cog.exempt.add((20, 10, 7))
    assert cog.flag_applies(7, 10)["source_guild_id"] == 10
    assert cog.flag_applies(7, 20)["source_guild_id"] == 30
    assert cog.flag_applies(7, 40)["source_guild_id"] == 10
    assert cog.flag_applies(7, 50) is None
    cog.flagged[(30, 7)]["expires_at_utc"] = (now_utc() - timedelta(seconds=1)).isoformat()
    assert cog.flag_applies(7, 20) is None


def test_evidence_urls_never_block_every_link_on_a_domain():
    cog = make_guardian()
    cog.flagged[(10, 7)] = flag()
    content = "Claim your reward https://example.org/scam?code=1"
    cog.fp_cache = [{"id": 1, "source_guild_id": 10, "user_id": 7, "hash": text_hash(content),
                     "urls": urls_of(content), "shas": set()}]
    msg = NS(guild=NS(id=10), content="Documentation: https://example.org/docs")
    assert cog.match_fingerprint(msg, set()) is None
    msg.content = "https://example.org/scam?code=1"
    assert "URL" in cog.match_fingerprint(msg, set())
    msg.guild.id = 20
    assert cog.match_fingerprint(msg, set()) is None


@pytest.mark.asyncio
async def test_local_pattern_removal_cannot_remove_source_servers_evidence(storage):
    await store.flag(10, 7, 1, "confirmed", None)
    pid = await store.add_pattern(10, 7, None, {"https://example.org/scam"}, set(), "", 100)
    await store.remove_pattern(20, pid)
    assert await db._one("SELECT id FROM guardian_patterns WHERE id=?", (pid,))
    assert await db._one("SELECT * FROM guardian_pattern_exempt WHERE guild_id=20 AND pattern_id=?", (pid,))


@pytest.mark.asyncio
async def test_log_routes_cannot_write_to_a_foreign_server(storage):
    cog = make_guardian()
    foreign = NS(guild=NS(id=20))
    cog.bot.get_channel = lambda _: foreign
    cog.routes[(10, "messages")] = 200
    assert await cog.log_channel(10, "messages") is None
    await db.enable_all_logging(10, 200)
    assert await cog.log_channel(10, "security") is None


def test_audit_matching_never_consumes_a_different_servers_entry():
    cog = make_guardian()
    for gid in (10, 20):
        cog.audit_buf.append(dict(guild_id=gid, action="message_delete", ts=time.monotonic(),
                                  left=1, target=7, channel=100, keys={"nick"}, actor=gid))
    assert cog.consume("message_delete", guild_id=10, target=7)["actor"] == 10
    assert cog.audit_buf[-1]["left"] == 1
    assert cog.find_recent("message_delete", guild_id=30, target=7) is None


@pytest.mark.asyncio
async def test_flag_clear_restores_previous_moderators_timeout(storage):
    previous = now_utc() + timedelta(hours=1)
    guild, member = make_guild(timeout=previous)
    cog = make_guardian([guild])
    assert await cog.apply_timeout(guild, 7, now_utc() + timedelta(hours=2), "confirmed", 10) == "timed out"
    assert await cog.release_owned_timeout(guild, 7)
    assert member.timed_out_until == previous
    assert await store.timeout_record(10, 7) is None


@pytest.mark.asyncio
async def test_external_timeout_edit_is_never_removed(storage):
    guild, member = make_guild()
    cog = make_guardian([guild])
    await cog.apply_timeout(guild, 7, now_utc() + timedelta(hours=2), "confirmed", 10)
    changed = now_utc() + timedelta(hours=3)
    member.timed_out_until = changed
    assert not await cog.release_owned_timeout(guild, 7)
    assert member.timed_out_until == changed
    assert member.timeout.await_count == 1
    assert await store.timeout_record(10, 7) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("policy_change", ["revoke_trust", "disable_network", "report_only"])
async def test_receiving_server_can_restore_owned_timeout_when_policy_changes(storage, policy_change):
    guild, member = make_guild(20)
    cog = make_guardian([guild])
    cog.network_enabled.add(20)
    cog.trusted_sources.add((20, 10))
    cog.flagged[(10, 7)] = flag()
    await cog.apply_timeout(guild, 7, now_utc() + timedelta(hours=2), "confirmed", 10)
    if policy_change == "revoke_trust":
        cog.trusted_sources.clear()
    elif policy_change == "disable_network":
        cog.network_enabled.clear()
    else:
        cog.report_only.add(20)
    assert await cog.release_owned_timeout(guild, 7)
    assert member.timed_out_until is None


@pytest.mark.asyncio
async def test_longer_existing_timeout_is_never_claimed_or_shortened(storage):
    previous = now_utc() + timedelta(days=2)
    guild, member = make_guild(timeout=previous)
    cog = make_guardian([guild])
    assert await cog.apply_timeout(guild, 7, now_utc() + timedelta(hours=2), "confirmed", 10) == "existing timeout retained"
    assert member.timed_out_until == previous
    member.timeout.assert_not_awaited()
    assert await store.timeout_record(10, 7) is None


@pytest.mark.asyncio
async def test_new_flag_is_not_disclosed_via_an_existing_different_source_flag(storage, monkeypatch):
    guild_a, member = make_guild(10)
    guild_c, _ = make_guild(30)
    cog = make_guardian([guild_a, guild_c])
    await store.flag(20, 7, 3, "old source B report", None)
    await store.trust(30, 20, True)
    await store.set_option(30, "network_enabled", True)
    await cog.refresh_cache()
    actor = NS(id=2, top_role=5)
    ctx = NS(guild=guild_a, author=actor, interaction=None, message=NS(reference=None), send=AsyncMock())
    cog.apply_timeout = AsyncMock(return_value="timed out")
    cog.send_log = AsyncMock()
    await Guardian.compromised.callback(cog, ctx, member, "24h", reason="private source A report")
    assert [call.args[0] for call in cog.send_log.await_args_list] == [10]
    assert [call.args[0].id for call in cog.apply_timeout.await_args_list] == [10]


@pytest.mark.asyncio
async def test_edited_attachment_is_scanned_even_when_archiving_is_disabled(storage, monkeypatch):
    guild, member = make_guild()
    cog = make_guardian([guild])
    cog.flagged[(10, 8)] = flag(uid=8)
    malware = b"confirmed malicious attachment content"
    cog.fp_cache = [{"id": 1, "source_guild_id": 10, "user_id": 8, "hash": None,
                     "urls": set(), "shas": {hashlib.sha256(malware).hexdigest()}}]
    attachment = NS(size=len(malware), read=AsyncMock(return_value=malware))
    channel = NS(id=100, guild=guild, mention="<#100>")
    message = NS(id=101, guild=guild, author=member, content="", channel=channel,
                 attachments=[attachment], delete=AsyncMock())
    channel.fetch_message = AsyncMock(return_value=message)
    cog.bot.get_channel = lambda _: channel
    cog.archive_allowed = AsyncMock(return_value=False)
    cog.send_log = AsyncMock()
    payload = NS(guild_id=10, channel_id=100, message_id=101, data={"attachments": [{}]})
    await cog.on_raw_message_edit(payload)
    worker = asyncio.create_task(cog.media_worker())
    try:
        await asyncio.wait_for(cog.media_queue.join(), timeout=2)
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
    attachment.read.assert_awaited_once()
    message.delete.assert_awaited_once()
    assert await db.get_attachments(101) == []


@pytest.mark.asyncio
async def test_media_work_queue_is_bounded():
    guild, member = make_guild()
    cog = make_guardian()
    cog.enforce = AsyncMock(return_value=False)
    cog.archive_allowed = AsyncMock(return_value=False)
    cog.needs_attachment_scan = lambda gid: True
    message = NS(guild=guild, author=member, attachments=[NS()])
    for _ in range(MEDIA_QUEUE_SIZE + 5):
        await cog.on_message(message)
    assert cog.media_queue.qsize() == MEDIA_QUEUE_SIZE
    assert cog.media_dropped == 5


@pytest.mark.asyncio
async def test_purge_rechecks_actor_permissions_before_deleting(storage):
    guild, _ = make_guild()
    cog = make_guardian([guild])
    actor = NS(id=2, top_role=5, mention="<@2>", guild_permissions=NS(manage_messages=True))
    actor_after_revoke = NS(id=2, top_role=5)
    guild.fetch_member = AsyncMock(return_value=actor_after_revoke)

    class Channel:
        id = 100
        mention = "<#100>"
        purge = AsyncMock()

        def permissions_for(self, who):
            return NS(view_channel=True, read_message_history=True, manage_messages=who is not actor_after_revoke)

    channel = Channel()
    guild.get_channel_or_thread = lambda _: channel
    status = NS(id=1000, edit=AsyncMock())
    ctx = NS(guild=guild, channel=channel, author=actor, send=AsyncMock(return_value=status))
    await Guardian.alarmbot.callback(cog, ctx, raw="-d -u 100000000000000 -t 1h")
    channel.purge.assert_not_awaited()
    assert "permissions changed" in status.edit.await_args.kwargs["content"]
