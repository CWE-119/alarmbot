import os
os.environ['BOT_TESTING'] = '1'

import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
import alarm_store
import community_store
import database as db
import guardian_store


@pytest_asyncio.fixture
async def stores(tmp_path, monkeypatch):
    await db.close_db()
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'integration.db'))
    await db.init_db()
    await alarm_store.init_db()
    await community_store.init_db()
    await guardian_store.init()
    yield
    await db.close_db()


@pytest.mark.asyncio
async def test_erasure_keeps_foreign_reminders_and_active_security(stores):
    when = datetime.now(timezone.utc) + timedelta(days=1)
    for gid in (10, 20):
        await alarm_store.add(1, gid, gid*100, 'channel', when, 'UTC', None, 'mine')
        await guardian_store.flag(gid, 1, 2, 'confirmed evidence', None)
    await db.forget_user(1, guild_id=10)
    assert len(await db._all('SELECT * FROM alarms WHERE guild_id=20')) == 1
    assert await db._all('SELECT * FROM alarms WHERE guild_id=10') == []
    assert len(await db._all('SELECT * FROM guardian_flags')) == 2


@pytest.mark.asyncio
async def test_erasing_event_creator_only_cancels_local_events(stores):
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    for gid in (10, 20):
        await community_store.create_event(gid, 1, 100*gid, 'My event', future)
        await community_store.set_dm_preference(gid, 1, True)
    await db.forget_user(1, guild_id=10)
    rows = await db._all('SELECT * FROM community_events ORDER BY guild_id')
    assert rows[0]['state'] == 'cancelled'
    assert rows[0]['creator_id'] == 0
    assert rows[1]['state'] == 'scheduled'
    assert rows[1]['creator_id'] == 1
    prefs = await db._all('SELECT * FROM community_event_preferences')
    assert [row['guild_id'] for row in prefs] == [20]


@pytest.mark.asyncio
async def test_export_never_contains_confidential_allegations(stores):
    await community_store.create_case(10, 2, 1, 'private accusation', 'private evidence')
    await community_store.create_case(20, 1, 2, 'other server report', 'other evidence')
    exported = await db.export_user(1, 10)
    assert 'private accusation' not in str(exported)
    assert 'other server report' not in str(exported)
    await db.forget_user(1, guild_id=10)
    assert len(await db._all('SELECT * FROM community_cases')) == 2


def test_dotenv_storage_is_loaded_before_configuration_and_import_does_not_write(tmp_path):
    source = Path(db.__file__).read_text()
    copied = tmp_path / 'database.py'
    copied.write_text(source)
    configured = tmp_path / 'persistent'
    (tmp_path / '.env').write_text(f'DATA_DIR={configured}\nRETENTION_DAYS=30\n')
    env = dict(os.environ)
    env.pop('DATA_DIR', None)
    env['PYTHONPATH'] = str(tmp_path)
    result = subprocess.run([sys.executable, '-c',
        'import database; from pathlib import Path; print(database.DB_PATH); assert not Path(database.DB_PATH).parent.exists()'],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert str(configured / 'alarm_bot.db') in result.stdout
