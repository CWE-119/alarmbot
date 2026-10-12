"""Guild-scoped reports, security settings and opt-in event reminders."""
from datetime import datetime, timedelta, timezone

import aiosqlite

import database as db

SCHEMA = """
CREATE TABLE IF NOT EXISTS community_settings (
    guild_id INTEGER PRIMARY KEY, report_channel_id INTEGER
);
CREATE TABLE IF NOT EXISTS community_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
    reporter_id INTEGER NOT NULL, target_id INTEGER NOT NULL, reason TEXT NOT NULL,
    evidence TEXT, message_url TEXT, created_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open', resolved_by INTEGER, resolution TEXT
);
CREATE INDEX IF NOT EXISTS community_cases_guild ON community_cases(guild_id, state, id);
CREATE TABLE IF NOT EXISTS community_case_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL, case_id INTEGER NOT NULL,
    actor_id INTEGER NOT NULL, action TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS community_actions_case ON community_case_actions(guild_id, case_id, id);
CREATE TABLE IF NOT EXISTS community_security (
    guild_id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0,
    alert_channel_id INTEGER, message_limit INTEGER NOT NULL DEFAULT 8,
    mention_limit INTEGER NOT NULL DEFAULT 10, window_seconds INTEGER NOT NULL DEFAULT 10,
    join_limit INTEGER NOT NULL DEFAULT 8, join_window_seconds INTEGER NOT NULL DEFAULT 20,
    action TEXT NOT NULL DEFAULT 'alert', share_signals INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS community_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
    creator_id INTEGER NOT NULL, channel_id INTEGER NOT NULL, message_id INTEGER,
    title TEXT NOT NULL, scheduled_at TEXT NOT NULL, created_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'scheduled'
);
CREATE INDEX IF NOT EXISTS community_events_due ON community_events(state, scheduled_at);
CREATE TABLE IF NOT EXISTS community_event_preferences (
    guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, dm_opt_in INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS community_event_subscriptions (
    event_id INTEGER NOT NULL, guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    dm_opt_in INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(event_id, user_id)
);
CREATE TABLE IF NOT EXISTS community_event_delivery (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, guild_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL, channel_id INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL, lease_until TEXT, last_error TEXT,
    UNIQUE(event_id, user_id)
);
CREATE INDEX IF NOT EXISTS community_delivery_due ON community_event_delivery(state, next_attempt_at);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


async def init_db():
    for statement in SCHEMA.split(';'):
        if statement.strip():
            await db._run(statement)


async def create_case(guild_id, reporter_id, target_id, reason, evidence='', message_url=None):
    return await db._insert("""INSERT INTO community_cases
        (guild_id,reporter_id,target_id,reason,evidence,message_url,created_at)
        VALUES (?,?,?,?,?,?,?)""", (guild_id, reporter_id, target_id, reason[:1800],
                                      evidence[:1800], message_url, now_iso()))


async def get_case(guild_id, case_id):
    return await db._one('SELECT * FROM community_cases WHERE guild_id=? AND id=?', (guild_id, case_id))


async def list_cases(guild_id, state='open'):
    return await db._all('SELECT * FROM community_cases WHERE guild_id=? AND state=? ORDER BY id DESC LIMIT 20',
                         (guild_id, state))


async def case_actions(guild_id, case_id):
    return await db._all('SELECT * FROM community_case_actions WHERE guild_id=? AND case_id=? ORDER BY id DESC LIMIT 10',
                         (guild_id, case_id))


async def record_action(guild_id, case_id, actor_id, action, note):
    return await db._run("""INSERT INTO community_case_actions
        (guild_id,case_id,actor_id,action,note,created_at)
        SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM community_cases WHERE guild_id=? AND id=?)""",
                         (guild_id, case_id, actor_id, action, note[:1800], now_iso(), guild_id, case_id))


async def resolve_case(guild_id, case_id, actor_id, resolution):
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        cur = await con.execute("""UPDATE community_cases SET state='resolved',resolved_by=?,resolution=?
            WHERE guild_id=? AND id=? AND state IN ('open','appealed')
            AND (state!='appealed' OR resolved_by IS NULL OR resolved_by!=?)""",
                                (actor_id, resolution[:1800], guild_id, case_id, actor_id))
        if cur.rowcount:
            await con.execute("""INSERT INTO community_case_actions
                (guild_id,case_id,actor_id,action,note,created_at) VALUES (?,?,?,'resolve',?,?)""",
                              (guild_id, case_id, actor_id, resolution[:1800], now_iso()))
        await con.commit()
        return bool(cur.rowcount)


async def appeal_case(guild_id, case_id, user_id, explanation):
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        cur = await con.execute("""UPDATE community_cases SET state='appealed'
            WHERE guild_id=? AND id=? AND state='resolved' AND (reporter_id=? OR target_id=?)""",
                                (guild_id, case_id, user_id, user_id))
        if cur.rowcount:
            await con.execute("""INSERT INTO community_case_actions
                (guild_id,case_id,actor_id,action,note,created_at) VALUES (?,?,?,'appeal',?,?)""",
                              (guild_id, case_id, user_id, explanation[:1800], now_iso()))
        await con.commit()
        return bool(cur.rowcount)


async def report_channel(guild_id):
    row = await db._one('SELECT report_channel_id FROM community_settings WHERE guild_id=?', (guild_id,))
    return row['report_channel_id'] if row else None


async def set_report_channel(guild_id, channel_id):
    await db._run("""INSERT INTO community_settings VALUES (?,?) ON CONFLICT(guild_id)
        DO UPDATE SET report_channel_id=excluded.report_channel_id""", (guild_id, channel_id))


async def security_settings():
    return {r['guild_id']: r for r in await db._all('SELECT * FROM community_security')}


async def configure_security(guild_id, enabled, alert_channel_id, message_limit, mention_limit,
                             window_seconds, join_limit, join_window_seconds, action, share_signals):
    await db._run("""INSERT INTO community_security VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(guild_id) DO UPDATE SET enabled=excluded.enabled,alert_channel_id=excluded.alert_channel_id,
        message_limit=excluded.message_limit,mention_limit=excluded.mention_limit,
        window_seconds=excluded.window_seconds,join_limit=excluded.join_limit,
        join_window_seconds=excluded.join_window_seconds,action=excluded.action,share_signals=excluded.share_signals""",
                  (guild_id, int(enabled), alert_channel_id, message_limit, mention_limit,
                   window_seconds, join_limit, join_window_seconds, action, int(share_signals)))


async def create_event(guild_id, creator_id, channel_id, title, scheduled_at):
    # Keep the quota check and insert atomic across concurrent slash commands.
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        await con.execute('BEGIN IMMEDIATE')
        cur = await con.execute("""SELECT COUNT(*), SUM(creator_id=?) FROM community_events
            WHERE guild_id=? AND state IN ('scheduled','dispatching')""", (creator_id, guild_id))
        total, mine = await cur.fetchone()
        if total >= 30 or (mine or 0) >= 5:
            return None
        cur = await con.execute("""INSERT INTO community_events
            (guild_id,creator_id,channel_id,title,scheduled_at,created_at) VALUES (?,?,?,?,?,?)""",
                                (guild_id, creator_id, channel_id, title[:150], scheduled_at, now_iso()))
        await con.commit()
        return cur.lastrowid


async def get_event(guild_id, event_id):
    return await db._one('SELECT * FROM community_events WHERE guild_id=? AND id=?', (guild_id, event_id))


async def active_events(guild_id=None):
    if guild_id is None:
        return await db._all("SELECT * FROM community_events WHERE state='scheduled'")
    return await db._all("SELECT * FROM community_events WHERE guild_id=? AND state='scheduled' ORDER BY scheduled_at LIMIT 30",
                         (guild_id,))


async def set_event_message(guild_id, event_id, message_id):
    await db._run('UPDATE community_events SET message_id=? WHERE guild_id=? AND id=?', (message_id, guild_id, event_id))


async def subscribe(guild_id, event_id, user_id):
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        await con.execute('BEGIN IMMEDIATE')
        cur = await con.execute("SELECT 1 FROM community_events WHERE guild_id=? AND id=? AND state='scheduled'",
                                (guild_id, event_id))
        if not await cur.fetchone():
            return None
        cur = await con.execute('SELECT COUNT(*) FROM community_event_subscriptions WHERE event_id=?', (event_id,))
        if (await cur.fetchone())[0] >= 80:
            cur = await con.execute('SELECT 1 FROM community_event_subscriptions WHERE event_id=? AND user_id=?', (event_id, user_id))
            if not await cur.fetchone():
                return None
        cur = await con.execute('SELECT dm_opt_in FROM community_event_preferences WHERE guild_id=? AND user_id=?', (guild_id, user_id))
        pref = await cur.fetchone()
        dm = int(pref[0]) if pref else 0
        await con.execute("""INSERT INTO community_event_subscriptions VALUES (?,?,?,?)
            ON CONFLICT(event_id,user_id) DO UPDATE SET dm_opt_in=excluded.dm_opt_in""", (event_id, guild_id, user_id, dm))
        await con.commit()
        return bool(dm)


async def unsubscribe(guild_id, event_id, user_id):
    await db._run('DELETE FROM community_event_subscriptions WHERE guild_id=? AND event_id=? AND user_id=?',
                  (guild_id, event_id, user_id))


async def event_subscriptions(guild_id, event_id):
    return await db._all('SELECT * FROM community_event_subscriptions WHERE guild_id=? AND event_id=?', (guild_id, event_id))


async def set_dm_preference(guild_id, user_id, dm_opt_in):
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        await con.execute("""INSERT INTO community_event_preferences VALUES (?,?,?)
            ON CONFLICT(guild_id,user_id) DO UPDATE SET dm_opt_in=excluded.dm_opt_in""", (guild_id, user_id, int(dm_opt_in)))
        await con.execute("""UPDATE community_event_subscriptions SET dm_opt_in=? WHERE guild_id=? AND user_id=?
            AND event_id IN (SELECT id FROM community_events WHERE state IN ('scheduled','dispatching'))""", (int(dm_opt_in), guild_id, user_id))
        await con.commit()


async def cancel_event(guild_id, event_id):
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        cur = await con.execute("UPDATE community_events SET state='cancelled' WHERE guild_id=? AND id=? AND state IN ('scheduled','dispatching')",
                                (guild_id, event_id))
        await con.execute("UPDATE community_event_delivery SET state='cancelled' WHERE guild_id=? AND event_id=? AND state IN ('pending','sending')",
                          (guild_id, event_id))
        await con.commit()
        return bool(cur.rowcount)


async def prepare_due_events(now=None):
    now = now or now_iso()
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        await con.execute('BEGIN IMMEDIATE')
        cur = await con.execute("SELECT id,guild_id,channel_id FROM community_events WHERE state='scheduled' AND scheduled_at<=? LIMIT 20", (now,))
        for event_id, guild_id, channel_id in await cur.fetchall():
            await con.execute("UPDATE community_events SET state='dispatching' WHERE id=?", (event_id,))
            await con.execute("""INSERT OR IGNORE INTO community_event_delivery
                (event_id,guild_id,user_id,channel_id,next_attempt_at) VALUES (?,?,0,?,?)""", (event_id, guild_id, channel_id, now))
            await con.execute("""INSERT OR IGNORE INTO community_event_delivery
                (event_id,guild_id,user_id,channel_id,next_attempt_at)
                SELECT event_id,guild_id,user_id,?,? FROM community_event_subscriptions WHERE event_id=? AND dm_opt_in=1""",
                              (channel_id, now, event_id))
        await con.commit()


async def due_deliveries(now=None):
    now = now or now_iso()
    return await db._all("""SELECT d.* FROM community_event_delivery d JOIN community_events e ON e.id=d.event_id
        WHERE e.state='dispatching' AND ((d.state='pending' AND d.next_attempt_at<=?) OR
        (d.state='sending' AND d.lease_until<=?)) ORDER BY d.next_attempt_at LIMIT 10""", (now, now))


async def claim_delivery(delivery_id, now=None):
    now = now or now_iso()
    lease = (datetime.fromisoformat(now) + timedelta(minutes=3)).isoformat()
    changed = await db._run("""UPDATE community_event_delivery SET state='sending',attempts=attempts+1,lease_until=?
        WHERE id=? AND event_id IN (SELECT id FROM community_events WHERE state='dispatching')
        AND ((state='pending' AND next_attempt_at<=?) OR (state='sending' AND lease_until<=?))""",
                           (lease, delivery_id, now, now))
    return await db._one('SELECT * FROM community_event_delivery WHERE id=?', (delivery_id,)) if changed else None


async def finish_delivery(delivery_id, state='sent', error=None):
    await db._run("""UPDATE community_event_delivery SET state=?,lease_until=NULL,last_error=?
        WHERE id=? AND state='sending'""", (state, error, delivery_id))


async def retry_delivery(delivery, error):
    if delivery['attempts'] >= 5:
        await finish_delivery(delivery['id'], 'failed', error)
    else:
        later = (datetime.now(timezone.utc) + timedelta(seconds=min(3600, 30 * 2 ** delivery['attempts']))).isoformat()
        await db._run("""UPDATE community_event_delivery SET state='pending',lease_until=NULL,next_attempt_at=?,last_error=?
            WHERE id=? AND state='sending'""", (later, error, delivery['id']))


async def finalize_events():
    await db._run("""UPDATE community_events SET state=CASE WHEN EXISTS
        (SELECT 1 FROM community_event_delivery d WHERE d.event_id=community_events.id AND d.state='failed')
        THEN 'failed' ELSE 'completed' END WHERE state='dispatching' AND NOT EXISTS
        (SELECT 1 FROM community_event_delivery d WHERE d.event_id=community_events.id AND d.state IN ('pending','sending'))""")


async def remove_member(guild_id, user_id):
    await db._run('DELETE FROM community_event_subscriptions WHERE guild_id=? AND user_id=?', (guild_id, user_id))
    await db._run('DELETE FROM community_event_preferences WHERE guild_id=? AND user_id=?', (guild_id, user_id))


async def purge_guild(guild_id):
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        for table in ('community_settings','community_case_actions','community_cases','community_security',
                      'community_event_delivery','community_event_subscriptions','community_event_preferences','community_events'):
            await con.execute(f'DELETE FROM {table} WHERE guild_id=?', (guild_id,))
        await con.commit()


async def prune(days=90, guild_id=None):
    """Prune only resolved cases and finished events in the requested server.

    The privacy retention worker supplies each server's chosen retention. Zero
    means keep data; an absent server is reserved for explicit maintenance.
    """
    if days <= 0:
        return
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    scope = ' AND guild_id=?' if guild_id is not None else ''
    args = (cutoff, guild_id) if guild_id is not None else (cutoff,)
    cases = "SELECT id FROM community_cases WHERE created_at<? AND state='resolved'" + scope
    events = "SELECT id FROM community_events WHERE scheduled_at<? AND state IN ('completed','cancelled','failed')" + scope
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as con:
        await con.execute('DELETE FROM community_case_actions WHERE case_id IN (' + cases + ')', args)
        await con.execute("DELETE FROM community_cases WHERE created_at<? AND state='resolved'" + scope, args)
        for table in ('community_event_delivery','community_event_subscriptions'):
            await con.execute(f'DELETE FROM {table} WHERE event_id IN (' + events + ')', args)
        await con.execute("DELETE FROM community_events WHERE scheduled_at<? AND state IN ('completed','cancelled','failed')" + scope, args)
        await con.commit()
