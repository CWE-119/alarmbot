
import aiosqlite
from datetime import datetime, timedelta
import pytz
from typing import Optional, List, Dict, Union, Any
from enum import Enum
import logging

# Setup logging
logger = logging.getLogger(__name__)

# Define RepeatType enum
class RepeatType(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

DB_NAME = "alarm_bot.db"

async def init_db() -> None:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute("""
            CREATE TABLE IF NOT EXISTS alarms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                channel_id INTEGER NOT NULL,
                time TEXT NOT NULL,
                message TEXT,
                timezone TEXT,
                repeat TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
            await db.execute("""
            CREATE TABLE IF NOT EXISTS user_timezones (
                user_id INTEGER PRIMARY KEY,
                timezone TEXT NOT NULL
            )""")
            await db.execute("""
            CREATE TABLE IF NOT EXISTS log_settings (
                guild_id INTEGER PRIMARY KEY,
                channel_id INTEGER,
                log_deletes BOOLEAN
            )""")
            # Add indexes for better query performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_alarms_time ON alarms(time)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_alarms_user ON alarms(user_id)")
            await db.commit()
    except Exception as e:
        logger.error("Database initialization error", exc_info=True)
        raise

async def add_alarm(user_id: int, dt: datetime, message: str, channel_id: int, timezone: str, repeat: Optional[RepeatType] = None) -> int:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            cursor = await db.execute("""
                INSERT INTO alarms (user_id, time, message, channel_id, timezone, repeat)
                VALUES (?, ?, ?, ?, ?, ?)""", 
                (user_id, dt.isoformat(), message, channel_id, timezone, repeat))
            await db.commit()
            cursor = await db.execute("SELECT last_insert_rowid()")
            row = await cursor.fetchone()
            return row[0]
    except Exception as e:
        logger.error("Error adding alarm", exc_info=True)
        raise

async def get_user_alarms(user_id: int) -> List[Dict[str, Any]]:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT id, time, message, timezone, repeat, channel_id 
                FROM alarms WHERE user_id = ? 
                ORDER BY time ASC""", (user_id,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Error fetching user alarms", exc_info=True)
        return []

async def get_due_alarms() -> List[Dict[str, Any]]:
    try:
        now = datetime.now(pytz.UTC).isoformat()
        async with aiosqlite.connect(DB_NAME) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM alarms WHERE time <= ?", (now,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error("Error fetching due alarms", exc_info=True)
        return []

async def update_alarm_time(alarm_id: int, new_time: datetime) -> None:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute("UPDATE alarms SET time = ? WHERE id = ?", 
                           (new_time.isoformat(), alarm_id))
            await db.commit()
    except Exception as e:
        logger.error("Error updating alarm time", exc_info=True)
        raise

async def delete_alarm(alarm_id: int) -> None:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute("DELETE FROM alarms WHERE id = ?", (alarm_id,))
            await db.commit()
    except Exception as e:
        logger.error("Error deleting alarm", exc_info=True)
        raise

async def set_user_timezone(user_id: int, timezone: str) -> None:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute("""
                INSERT INTO user_timezones (user_id, timezone)
                VALUES (?, ?)
                ON CONFLICT(user_id) DO UPDATE SET timezone = excluded.timezone
                """, (user_id, timezone))
            await db.commit()
    except Exception as e:
        logger.error("Error setting user timezone", exc_info=True)
        raise

async def get_user_timezone(user_id: int) -> str:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            cursor = await db.execute("SELECT timezone FROM user_timezones WHERE user_id = ?", 
                                    (user_id,))
            row = await cursor.fetchone()
            return row[0] if row else "UTC"
    except Exception as e:
        logger.error("Database error in get_user_timezone", exc_info=True)
        return "UTC"

async def set_log_channel(guild_id: int, channel_id: int) -> None:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute("""
                INSERT INTO log_settings (guild_id, channel_id, log_deletes)
                VALUES (?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET channel_id = excluded.channel_id
                """, (guild_id, channel_id, True))
            await db.commit()
    except Exception as e:
        logger.error("Error setting log channel", exc_info=True)
        raise

async def get_log_settings(guild_id: int) -> Optional[tuple]:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            cursor = await db.execute("""
                SELECT channel_id, log_deletes FROM log_settings 
                WHERE guild_id = ?""", (guild_id,))
            return await cursor.fetchone()
    except Exception as e:
        logger.error("Error getting log settings", exc_info=True)
        return None

async def toggle_delete_logging(guild_id: int) -> Optional[bool]:
    try:
        async with aiosqlite.connect(DB_NAME) as db:
            cursor = await db.execute("SELECT log_deletes FROM log_settings WHERE guild_id = ?", 
                                    (guild_id,))
            row = await cursor.fetchone()
            if row is None:
                return None
            new_val = not bool(row[0])
            await db.execute("UPDATE log_settings SET log_deletes = ? WHERE guild_id = ?",
                           (new_val, guild_id))
            await db.commit()
            return new_val
    except Exception as e:
        logger.error("Error toggling delete logging", exc_info=True)
        return None

async def cleanup_expired_alarms(days: int = 7) -> None:
    try:
        cutoff_date = (datetime.now(pytz.UTC) - timedelta(days=days)).isoformat()
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute("""
                DELETE FROM alarms 
                WHERE time < ? AND repeat IS NULL
                """, (cutoff_date,))
            await db.commit()
    except Exception as e:
        logger.error("Error cleaning up expired alarms", exc_info=True)
