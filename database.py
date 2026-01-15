# database.py
import aiosqlite
from datetime import datetime, timedelta
import pytz

DB_PATH = "alarm_bot.db"

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF NOT EXISTS user_timezones (
            user_id INTEGER PRIMARY KEY,
            timezone TEXT NOT NULL DEFAULT 'UTC'
        )
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS alarms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            time_utc TEXT NOT NULL,
            message TEXT NOT NULL,
            channel_id INTEGER,
            timezone TEXT NOT NULL DEFAULT 'UTC',
            repeat TEXT,              -- 'daily' | 'weekly' | NULL
            paused INTEGER NOT NULL DEFAULT 0,
            created_at_utc TEXT NOT NULL
        )
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS guild_log_settings (
            guild_id INTEGER PRIMARY KEY,
            log_channel_id INTEGER,
            log_deletes INTEGER NOT NULL DEFAULT 0,
            log_edits INTEGER NOT NULL DEFAULT 0,
            log_bulk_deletes INTEGER NOT NULL DEFAULT 0
        )
        """)
        await db.commit()

# ---------- Timezones ----------
async def set_user_timezone(user_id: int, timezone: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        INSERT INTO user_timezones (user_id, timezone)
        VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET timezone=excluded.timezone
        """, (user_id, timezone))
        await db.commit()

async def get_user_timezone(user_id: int) -> str:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT timezone FROM user_timezones WHERE user_id=?", (user_id,)) as cur:
            row = await cur.fetchone()
    return row[0] if row else "UTC"

# ---------- Alarms ----------
async def add_alarm(user_id: int, time_utc: datetime, message: str, channel_id: int | None, timezone: str, repeat: str | None):
    if time_utc.tzinfo is None:
        time_utc = pytz.UTC.localize(time_utc)
    time_utc_str = time_utc.astimezone(pytz.UTC).isoformat()
    created_at = datetime.now(pytz.UTC).isoformat()

    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
        INSERT INTO alarms (user_id, time_utc, message, channel_id, timezone, repeat, paused, created_at_utc)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        """, (user_id, time_utc_str, message, channel_id, timezone, repeat, created_at))
        await db.commit()
        return cur.lastrowid

async def get_user_alarms(user_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("""
            SELECT id, user_id, time_utc, message, channel_id, timezone, repeat, paused
            FROM alarms
            WHERE user_id=?
            ORDER BY time_utc ASC
        """, (user_id,)) as cur:
            rows = await cur.fetchall()

    alarms = []
    for r in rows:
        alarms.append({
            "id": r[0],
            "user_id": r[1],
            "time": r[2],
            "message": r[3],
            "channel_id": r[4],
            "timezone": r[5],
            "repeat": r[6],
            "paused": bool(r[7]),
        })
    return alarms

async def get_due_alarms():
    now_utc = datetime.now(pytz.UTC).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("""
            SELECT id, user_id, time_utc, message, channel_id, timezone, repeat, paused
            FROM alarms
            WHERE paused=0 AND time_utc <= ?
            ORDER BY time_utc ASC
        """, (now_utc,)) as cur:
            rows = await cur.fetchall()

    alarms = []
    for r in rows:
        alarms.append({
            "id": r[0],
            "user_id": r[1],
            "time": r[2],
            "message": r[3],
            "channel_id": r[4],
            "timezone": r[5],
            "repeat": r[6],
            "paused": bool(r[7]),
        })
    return alarms

async def delete_alarm(alarm_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM alarms WHERE id=?", (alarm_id,))
        await db.commit()

async def update_alarm_time(alarm_id: int, next_time_utc: datetime):
    if next_time_utc.tzinfo is None:
        next_time_utc = pytz.UTC.localize(next_time_utc)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE alarms SET time_utc=? WHERE id=?",
                         (next_time_utc.astimezone(pytz.UTC).isoformat(), alarm_id))
        await db.commit()

async def update_alarm(alarm_id: int, new_time_utc: datetime, repeat: str | None, message: str):
    if new_time_utc.tzinfo is None:
        new_time_utc = pytz.UTC.localize(new_time_utc)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            UPDATE alarms
            SET time_utc=?, repeat=?, message=?
            WHERE id=?
        """, (new_time_utc.astimezone(pytz.UTC).isoformat(), repeat, message, alarm_id))
        await db.commit()

async def set_alarm_paused(alarm_id: int, paused: bool):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE alarms SET paused=? WHERE id=?", (1 if paused else 0, alarm_id))
        await db.commit()

async def snooze_alarm(alarm_id: int, delta: timedelta):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT time_utc FROM alarms WHERE id=?", (alarm_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            return False
        old_time = datetime.fromisoformat(row[0])
        if old_time.tzinfo is None:
            old_time = pytz.UTC.localize(old_time)
        new_time = old_time + delta
        await db.execute("UPDATE alarms SET time_utc=? WHERE id=?", (new_time.astimezone(pytz.UTC).isoformat(), alarm_id))
        await db.commit()
        return True

# ---------- Logging settings ----------
async def set_log_channel(guild_id: int, channel_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        INSERT INTO guild_log_settings (guild_id, log_channel_id)
        VALUES (?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET log_channel_id=excluded.log_channel_id
        """, (guild_id, channel_id))
        await db.commit()

async def get_log_settings(guild_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("""
            SELECT log_channel_id, log_deletes, log_edits, log_bulk_deletes
            FROM guild_log_settings
            WHERE guild_id=?
        """, (guild_id,)) as cur:
            row = await cur.fetchone()
    return row  # (channel_id, deletes, edits, bulk)

async def toggle_delete_logging(guild_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT log_channel_id, log_deletes FROM guild_log_settings WHERE guild_id=?", (guild_id,)) as cur:
            row = await cur.fetchone()
        if not row or not row[0]:
            return None
        new_val = 0 if row[1] else 1
        await db.execute("UPDATE guild_log_settings SET log_deletes=? WHERE guild_id=?", (new_val, guild_id))
        await db.commit()
        return bool(new_val)

async def toggle_edit_logging(guild_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT log_channel_id, log_edits FROM guild_log_settings WHERE guild_id=?", (guild_id,)) as cur:
            row = await cur.fetchone()
        if not row or not row[0]:
            return None
        new_val = 0 if row[1] else 1
        await db.execute("UPDATE guild_log_settings SET log_edits=? WHERE guild_id=?", (new_val, guild_id))
        await db.commit()
        return bool(new_val)

async def toggle_bulk_delete_logging(guild_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT log_channel_id, log_bulk_deletes FROM guild_log_settings WHERE guild_id=?", (guild_id,)) as cur:
            row = await cur.fetchone()
        if not row or not row[0]:
            return None
        new_val = 0 if row[1] else 1
        await db.execute("UPDATE guild_log_settings SET log_bulk_deletes=? WHERE guild_id=?", (new_val, guild_id))
        await db.commit()
        return bool(new_val)
