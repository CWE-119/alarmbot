import os
os.environ['BOT_TESTING'] = '1'

import sqlite3
from pathlib import Path
import pytest
import pytest_asyncio
import database as db
import maintenance


@pytest_asyncio.fixture
async def storage(tmp_path, monkeypatch):
    await db.close_db()
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'test.db'))
    await db.init_db()
    yield tmp_path
    await db.close_db()


async def profile(uid):
    await db.upsert_profile({'user_id': uid, 'username': 'test', 'global_name': None,
                            'avatar_hash': 'common', 'created': '2020-01-01T00:00:00+00:00', 'is_bot': 0})


@pytest.mark.asyncio
async def test_history_is_strictly_local(storage):
    for gid in (10, 20, None):
        await db.add_history(1, gid, 'nickname', 'old', f'new-{gid}')
    rows = await db.get_history(1, 10)
    assert len(rows) == 1
    assert rows[0]['guild_id'] == 10


@pytest.mark.asyncio
async def test_alt_signals_exclude_other_server(storage):
    for uid in (1, 2, 3):
        await profile(uid)
    for gid, uid in ((10, 1), (10, 2), (20, 1), (20, 3)):
        await db.record_member_join(gid, uid, None, db.utcnow_iso(), None, None)
    assert 2 in await db.alt_signals(1, 10)
    assert 3 not in await db.alt_signals(1, 10)


@pytest.mark.asyncio
async def test_archive_exclusions_and_optouts_are_scoped(storage):
    await db.set_archive_exclusion(10, 100, True)
    assert not await db.should_archive(10, 101, 1, parent_ids=(100,))
    assert await db.should_archive(20, 101, 1, parent_ids=(100,))
    await db.set_capture_optout(1, 10, True)
    assert not await db.should_archive(10, 200, 1)
    assert await db.should_archive(20, 200, 1)
    await db.set_capture_optout(1, None, True)
    assert not await db.should_archive(20, 200, 1)
    assert await db.should_archive(20, 200, 2)


@pytest.mark.asyncio
async def test_scoped_forgetting_cannot_delete_other_server(storage):
    await db._run('ALTER TABLE alarms ADD COLUMN guild_id INTEGER')
    for gid in (10, 20):
        await db._run("INSERT INTO alarms(user_id,time_utc,message,created_at_utc,guild_id) VALUES (1, '2030-01-01', 'reminder', '2026-01-01', ?)", (gid,))
        await db.add_history(1, gid, 'nickname', 'a', 'b')
        await db.add_audit_event(gid, 'action', 1, 2, 'personal text')
    await db.set_user_timezone(1, 'Asia/Dhaka')
    await profile(1)
    await db.forget_user(1, guild_id=10)
    assert [r['guild_id'] for r in await db._all('SELECT * FROM alarms')] == [20]
    assert await db.get_history(1, 10) == []
    assert len(await db.get_history(1, 20)) == 1
    assert await db.get_user_timezone(1) == 'Asia/Dhaka'
    assert (await db.get_profile(1))['user_id'] == 1
    rows = await db._all('SELECT * FROM audit_events ORDER BY guild_id')
    assert rows[0]['actor_id'] == 0
    assert rows[1]['actor_id'] == 1
    await db.forget_user(1)
    assert await db._all('SELECT * FROM alarms') == []
    assert await db._all('SELECT * FROM user_timezones') == []
    assert await db.get_profile(1) is None


@pytest.mark.asyncio
async def test_retention_does_not_touch_other_server(storage):
    for mid, gid in ((1, 10), (2, 20)):
        await db.log_message(dict(message_id=mid,guild_id=gid,channel_id=100,author_id=1,
            author_name='test',content='text',content_hash=None,reply_to_id=None,created_at_utc='2020-01-01'))
        await db.log_edit(mid,'text','new',None)
    await db.prune_messages('2021-01-01', guild_id=10)
    assert await db.get_message(1) is None
    assert await db.get_message(2) is not None
    assert len(await db._all('SELECT * FROM message_edits')) == 1


@pytest.mark.asyncio
async def test_export_is_self_and_server_scoped(storage):
    for uid, gid in ((1, 10), (1, 20), (2, 10)):
        await db.record_member_join(gid, uid, 'nick', db.utcnow_iso(), 'private-invite', 5)
    export = await db.export_user(1, 10)
    assert len(export['guild_members']) == 1
    assert export['guild_members'][0]['guild_id'] == 10
    assert 'invite_code' not in export['guild_members'][0]


@pytest.mark.asyncio
async def test_backup_and_offline_restore(storage):
    await db.set_user_timezone(1, 'Asia/Dhaka')
    backup = storage / 'backup.db'
    maintenance.backup_database(db.DB_PATH, backup)
    assert maintenance.verify_backup(backup)
    await db.set_user_timezone(1, 'UTC')
    with pytest.raises(ValueError, match='Stop the bot'):
        maintenance.restore_database(backup, db.DB_PATH, replace=True)
    await db.close_db()
    previous = maintenance.restore_database(backup, db.DB_PATH, replace=True, bot_stopped=True)
    assert previous.exists()
    assert await db.get_user_timezone(1) == 'Asia/Dhaka'


@pytest.mark.asyncio
async def test_grouped_writes_rollback_together(storage):
    with pytest.raises(Exception):
        await db.run_transaction([
            ('INSERT INTO user_timezones VALUES (?,?)', (1,'UTC')),
            ('INSERT INTO nonexistent_table VALUES (?)', (1,)),
        ])
    assert await db._all('SELECT * FROM user_timezones') == []

@pytest.mark.asyncio
async def test_investigation_queries_reject_missing_server(storage):
    with pytest.raises(ValueError, match='server'):
        await db.get_history(1, None)
    with pytest.raises(ValueError, match='server'):
        await db.get_memberships(1, None)


@pytest.mark.asyncio
async def test_conditional_insert_cannot_return_previous_row_id(storage):
    await db._insert('INSERT INTO user_timezones VALUES (?,?)', (1, 'UTC'))
    result = await db._insert('INSERT INTO user_timezones SELECT ?,? WHERE 0', (2, 'UTC'))
    assert result == 0
    assert await db._one('SELECT * FROM user_timezones WHERE user_id=2') is None
