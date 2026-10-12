"""
database.py - SQLite storage for the alarm bot and the Guardian cog.

The SQLite file is the ONLY thing this bot writes to disk. Attachments and avatars are mirrored into
Discord log channels; the database stores text and the mirror URLs.
"""
import os
import asyncio
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from pathlib import Path

import aiosqlite
import pytz
from dotenv import load_dotenv

# ============================================================ configuration
# Absolute path, independent of the launch directory. On hosts with an ephemeral disk
# (Railway, Heroku, ...) point DATA_DIR at a persistent volume or settings are lost on restart.
load_dotenv(Path(__file__).resolve().parent / ".env")
DATA_DIR = Path(os.getenv("DATA_DIR") or (Path(__file__).resolve().parent / "data"))
DB_PATH = str(DATA_DIR / "alarm_bot.db")
_connection = None
_connection_path = None
_connection_lock = asyncio.Lock()

# ============================================================ schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS user_timezones (
    user_id INTEGER PRIMARY KEY,
    timezone TEXT NOT NULL DEFAULT 'UTC'
);

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
);

CREATE TABLE IF NOT EXISTS guild_log_settings (
    guild_id INTEGER PRIMARY KEY,
    log_channel_id INTEGER,
    log_deletes INTEGER NOT NULL DEFAULT 0,
    log_edits INTEGER NOT NULL DEFAULT 0,
    log_bulk_deletes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS guild_log_routes (
    guild_id INTEGER NOT NULL, category TEXT NOT NULL, channel_id INTEGER NOT NULL,   -- 0 = disabled
    PRIMARY KEY (guild_id, category)
);
CREATE TABLE IF NOT EXISTS guild_options (
    guild_id INTEGER PRIMARY KEY, media_mirror INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS guild_protection (
    guild_id INTEGER PRIMARY KEY, network_protection INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS message_log (
    message_id INTEGER PRIMARY KEY, guild_id INTEGER, channel_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL, author_name TEXT, content TEXT, reply_to_id INTEGER,
    created_at_utc TEXT NOT NULL, edited INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0, deleted_at_utc TEXT, content_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_msg_author ON message_log(author_id, created_at_utc);
CREATE INDEX IF NOT EXISTS idx_msg_chan ON message_log(channel_id, created_at_utc);
CREATE TABLE IF NOT EXISTS message_edits (
    id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL,
    old_content TEXT, new_content TEXT, edited_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL, guild_id INTEGER,
    channel_id INTEGER, author_id INTEGER, filename TEXT, url TEXT, mirror_url TEXT,
    sha256 TEXT, size INTEGER, content_type TEXT
);
CREATE INDEX IF NOT EXISTS idx_att_msg ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_att_sha ON attachments(sha256);

CREATE TABLE IF NOT EXISTS user_profiles (
    user_id INTEGER PRIMARY KEY, username TEXT, global_name TEXT, avatar_hash TEXT,
    account_created_utc TEXT, first_seen_utc TEXT, last_seen_utc TEXT, is_bot INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_prof_avatar ON user_profiles(avatar_hash);
CREATE TABLE IF NOT EXISTS profile_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, guild_id INTEGER,
    kind TEXT NOT NULL, old_value TEXT, new_value TEXT, mirror_url TEXT, changed_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hist_user ON profile_history(user_id);
CREATE TABLE IF NOT EXISTS avatar_mirrors (
    user_id INTEGER NOT NULL, avatar_hash TEXT NOT NULL, mirror_url TEXT NOT NULL, saved_at_utc TEXT,
    PRIMARY KEY (user_id, avatar_hash)
);
CREATE TABLE IF NOT EXISTS guild_members (
    guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, nickname TEXT, joined_at_utc TEXT,
    left_at_utc TEXT, invite_code TEXT, inviter_id INTEGER, PRIMARY KEY (guild_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_gm_user ON guild_members(user_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL, action TEXT NOT NULL,
    actor_id INTEGER, target_id INTEGER, summary TEXT, created_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events(guild_id, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(guild_id, actor_id);
CREATE TABLE IF NOT EXISTS purge_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER, invoker_id INTEGER,
    command TEXT, deleted_count INTEGER, ran_at_utc TEXT
);

CREATE TABLE IF NOT EXISTS compromised_users (
    user_id INTEGER PRIMARY KEY, flagged_by INTEGER, source_guild_id INTEGER, reason TEXT,
    flagged_at_utc TEXT, expires_at_utc TEXT, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS compromised_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, content_hash TEXT,
    domains TEXT, attachment_shas TEXT, sample TEXT, created_at_utc TEXT
);
CREATE TABLE IF NOT EXISTS compromised_exempt (
    guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY (guild_id, user_id)
);
"""

# for databases created by earlier versions (fresh installs already have these columns)
MIGRATIONS = (
    "ALTER TABLE attachments ADD COLUMN mirror_url TEXT",
    "ALTER TABLE profile_history ADD COLUMN mirror_url TEXT",
)


async def init_db():
    default_retention()
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    # Only the repository's legacy database is eligible, never an arbitrary cwd file.
    legacy = Path(__file__).resolve().parent / "alarm_bot.db"
    if legacy.exists() and not Path(DB_PATH).exists() and not os.getenv("BOT_TESTING"):
        with closing(sqlite3.connect(str(legacy))) as source, closing(sqlite3.connect(DB_PATH)) as target:
            source.backup(target)
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.executescript(SCHEMA)
        for stmt in MIGRATIONS:
            try:
                await db.execute(stmt)
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
        await db.executescript(PRIVACY_SCHEMA)
        await db.commit()


# ============================================================ helpers
def utcnow_iso() -> str:
    return datetime.now(pytz.UTC).isoformat()


def _utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = pytz.UTC.localize(dt)
    return dt.astimezone(pytz.UTC).isoformat()


async def _run(sql, params=()) -> int:
    """Execute a write; returns the affected row count."""
    async with _connection_lock:
        conn = await _get_connection()
        try:
            async with conn.execute(sql, params) as cur:
                count = cur.rowcount
            await conn.commit()
            return count
        except BaseException:
            await conn.rollback()
            raise


async def _insert(sql, params=()) -> int:
    """Execute an INSERT; returns the new row id."""
    async with _connection_lock:
        conn = await _get_connection()
        try:
            async with conn.execute(sql, params) as cur:
                ident = cur.lastrowid if cur.rowcount else 0
            await conn.commit()
            return ident
        except BaseException:
            await conn.rollback()
            raise


async def _all(sql, params=()) -> list:
    async with _connection_lock:
        conn = await _get_connection()
        async with conn.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def _get_connection():
    """Called under the lock: reuse one connection, serialize small transactions."""
    global _connection, _connection_path
    if _connection is not None and _connection_path != DB_PATH:
        await _connection.close()
        _connection = None
    if _connection is None:
        _connection = await aiosqlite.connect(DB_PATH, timeout=30)
        _connection.row_factory = aiosqlite.Row
        _connection_path = DB_PATH
    return _connection


async def close_db():
    global _connection, _connection_path, _connection_lock
    async with _connection_lock:
        if _connection is not None:
            await _connection.close()
        _connection = _connection_path = None
    _connection_lock = asyncio.Lock()


async def run_transaction(statements):
    async with _connection_lock:
        conn = await _get_connection()
        try:
            await conn.execute("BEGIN IMMEDIATE")
            for sql, params in statements:
                await conn.execute(sql, params)
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise


async def _one(sql, params=()):
    rows = await _all(sql, params)
    return rows[0] if rows else None


# ============================================================ timezones
async def set_user_timezone(user_id: int, timezone: str):
    await _run("""
        INSERT INTO user_timezones (user_id, timezone) VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET timezone=excluded.timezone
    """, (user_id, timezone))


async def get_user_timezone(user_id: int) -> str:
    row = await _one("SELECT timezone FROM user_timezones WHERE user_id=?", (user_id,))
    return row["timezone"] if row else "UTC"


# ============================================================ alarms
_ALARM_COLS = "id, user_id, time_utc AS time, message, channel_id, timezone, repeat, paused"


def _alarm(row: dict) -> dict:
    row["paused"] = bool(row["paused"])
    return row


async def add_alarm(user_id: int, time_utc: datetime, message: str, channel_id, timezone: str, repeat) -> int:
    return await _insert("""
        INSERT INTO alarms (user_id, time_utc, message, channel_id, timezone, repeat, paused, created_at_utc)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    """, (user_id, _utc_iso(time_utc), message, channel_id, timezone, repeat, utcnow_iso()))


async def get_user_alarms(user_id: int) -> list:
    rows = await _all(f"SELECT {_ALARM_COLS} FROM alarms WHERE user_id=? ORDER BY time_utc ASC", (user_id,))
    return [_alarm(r) for r in rows]


async def get_due_alarms() -> list:
    rows = await _all(f"SELECT {_ALARM_COLS} FROM alarms WHERE paused=0 AND time_utc <= ? ORDER BY time_utc ASC",
                      (utcnow_iso(),))
    return [_alarm(r) for r in rows]


async def delete_alarm(alarm_id: int):
    await _run("DELETE FROM alarms WHERE id=?", (alarm_id,))


async def update_alarm_time(alarm_id: int, next_time_utc: datetime):
    await _run("UPDATE alarms SET time_utc=? WHERE id=?", (_utc_iso(next_time_utc), alarm_id))


async def update_alarm(alarm_id: int, new_time_utc: datetime, repeat, message: str):
    await _run("UPDATE alarms SET time_utc=?, repeat=?, message=? WHERE id=?",
               (_utc_iso(new_time_utc), repeat, message, alarm_id))


async def set_alarm_paused(alarm_id: int, paused: bool):
    await _run("UPDATE alarms SET paused=? WHERE id=?", (1 if paused else 0, alarm_id))


async def snooze_alarm(alarm_id: int, delta: timedelta) -> bool:
    row = await _one("SELECT time_utc FROM alarms WHERE id=?", (alarm_id,))
    if not row:
        return False
    old = datetime.fromisoformat(row["time_utc"])
    await update_alarm_time(alarm_id, old + delta)
    return True


# ============================================================ log settings
async def get_log_settings(guild_id: int):
    """-> (channel_id, log_deletes, log_edits, log_bulk_deletes) or None."""
    r = await _one("""SELECT log_channel_id, log_deletes, log_edits, log_bulk_deletes
                      FROM guild_log_settings WHERE guild_id=?""", (guild_id,))
    return (r["log_channel_id"], r["log_deletes"], r["log_edits"], r["log_bulk_deletes"]) if r else None


async def enable_all_logging(guild_id: int, channel_id: int):
    await _run("""
        INSERT INTO guild_log_settings (guild_id, log_channel_id, log_deletes, log_edits, log_bulk_deletes)
        VALUES (?, ?, 1, 1, 1)
        ON CONFLICT(guild_id) DO UPDATE SET log_channel_id=excluded.log_channel_id,
            log_deletes=1, log_edits=1, log_bulk_deletes=1
    """, (guild_id, channel_id))


_LOG_FLAGS = {"log_deletes", "log_edits", "log_bulk_deletes"}


async def toggle_log_flag(guild_id: int, column: str):
    """Flip one logging flag. Returns the new state, or None if no log channel is set yet."""
    if column not in _LOG_FLAGS:
        raise ValueError(column)
    row = await _one(f"SELECT log_channel_id, {column} AS v FROM guild_log_settings WHERE guild_id=?", (guild_id,))
    if not row or not row["log_channel_id"]:
        return None
    new = 0 if row["v"] else 1
    await _run(f"UPDATE guild_log_settings SET {column}=? WHERE guild_id=?", (new, guild_id))
    return bool(new)


# ============================================================ profiles / membership
_PROFILE_UPSERT = """
    INSERT INTO user_profiles (user_id, username, global_name, avatar_hash, account_created_utc,
                               first_seen_utc, last_seen_utc, is_bot)
    VALUES (:user_id, :username, :global_name, :avatar_hash, :created, :now, :now, :is_bot)
    ON CONFLICT(user_id) DO UPDATE SET username=excluded.username, global_name=excluded.global_name,
        avatar_hash=excluded.avatar_hash, last_seen_utc=excluded.last_seen_utc
"""


async def upsert_profile(p: dict):
    await _run(_PROFILE_UPSERT, {**p, "now": utcnow_iso()})


async def touch_profile(p: dict):
    """Cheap per-message call: insert if new, otherwise only bump last_seen."""
    await _run("""
        INSERT INTO user_profiles (user_id, username, global_name, avatar_hash, account_created_utc,
                                   first_seen_utc, last_seen_utc, is_bot)
        VALUES (:user_id, :username, :global_name, :avatar_hash, :created, :now, :now, :is_bot)
        ON CONFLICT(user_id) DO UPDATE SET last_seen_utc=excluded.last_seen_utc
    """, {**p, "now": utcnow_iso()})


async def get_profile(user_id: int):
    return await _one("SELECT * FROM user_profiles WHERE user_id=?", (user_id,))


async def add_history(user_id: int, guild_id, kind: str, old, new, mirror_url=None):
    await _run("""
        INSERT INTO profile_history (user_id, guild_id, kind, old_value, new_value, mirror_url, changed_at_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, guild_id, kind, old, new, mirror_url, utcnow_iso()))


async def get_history(user_id: int, guild_id: int, limit: int = 15):
    """A guild query never returns another guild's or legacy global history."""
    if guild_id is None:
        raise ValueError("A server is required for investigation history")
    return await _all("""SELECT * FROM profile_history WHERE user_id=? AND guild_id=?
                         ORDER BY id DESC LIMIT ?""", (user_id, guild_id, limit))


async def sync_profiles(profiles: list, members: list, complete_guild_ids=None) -> int:
    """Startup bulk sync. Records history for anything that changed while the bot was offline."""
    now = utcnow_iso()
    present_by_guild = {}
    for member in members:
        present_by_guild.setdefault(member["guild_id"], set()).add(member["user_id"])
    members = [m for m in members if await should_archive(m["guild_id"], user_id=m["user_id"])]
    eligible = {m["user_id"] for m in members}
    profiles = [p for p in profiles if p["user_id"] in eligible]
    async with aiosqlite.connect(DB_PATH, timeout=60) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT user_id, username, global_name, avatar_hash FROM user_profiles") as cur:
            old = {r["user_id"]: dict(r) for r in await cur.fetchall()}
        async with db.execute("SELECT guild_id, user_id, nickname FROM guild_members") as cur:
            old_nick = {(r["guild_id"], r["user_id"]): r["nickname"] for r in await cur.fetchall()}

        hist = []
        for p in profiles:
            o = old.get(p["user_id"])
            if not o:
                continue
            for kind, key in (("username", "username"), ("global_name", "global_name"), ("avatar", "avatar_hash")):
                if o[key] != p[key]:
                    for member in members:
                        if member["user_id"] == p["user_id"]:
                            hist.append((p["user_id"], member["guild_id"], kind, o[key], p[key], None, now))
        for m in members:
            k = (m["guild_id"], m["user_id"])
            if k in old_nick and old_nick[k] != m["nickname"]:
                hist.append((m["user_id"], m["guild_id"], "nickname", old_nick[k], m["nickname"], None, now))

        await db.executemany(_PROFILE_UPSERT, [{**p, "now": now} for p in profiles])
        await db.executemany("""
            INSERT INTO guild_members (guild_id, user_id, nickname, joined_at_utc, left_at_utc)
            VALUES (:guild_id, :user_id, :nickname, :joined, NULL)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET nickname=excluded.nickname,
                joined_at_utc=COALESCE(excluded.joined_at_utc,guild_members.joined_at_utc), left_at_utc=NULL,
                invite_code=CASE WHEN guild_members.joined_at_utc!=excluded.joined_at_utc THEN NULL ELSE guild_members.invite_code END,
                inviter_id=CASE WHEN guild_members.joined_at_utc!=excluded.joined_at_utc THEN NULL ELSE guild_members.inviter_id END
        """, members)
        # Reconcile departures only for guilds whose member cache was fully loaded.
        for gid in complete_guild_ids or ():
            present = present_by_guild.get(gid, set())
            async with db.execute("SELECT user_id FROM guild_members WHERE guild_id=? AND left_at_utc IS NULL", (gid,)) as cur:
                departed = [(now, gid, r[0]) for r in await cur.fetchall() if r[0] not in present]
            await db.executemany("UPDATE guild_members SET left_at_utc=? WHERE guild_id=? AND user_id=?", departed)
        if hist:
            await db.executemany("""
                INSERT INTO profile_history (user_id, guild_id, kind, old_value, new_value, mirror_url, changed_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?)""", hist)
        await db.commit()
    return len(hist)


async def record_member_join(guild_id: int, user_id: int, nickname, joined_at_iso: str,
                             invite_code, inviter_id):
    await _run("""
        INSERT INTO guild_members (guild_id, user_id, nickname, joined_at_utc, left_at_utc, invite_code, inviter_id)
        VALUES (?, ?, ?, ?, NULL, ?, ?)
        ON CONFLICT(guild_id, user_id) DO UPDATE SET nickname=excluded.nickname,
            joined_at_utc=excluded.joined_at_utc, left_at_utc=NULL,
            invite_code=excluded.invite_code, inviter_id=excluded.inviter_id
    """, (guild_id, user_id, nickname, joined_at_iso, invite_code, inviter_id))


async def mark_member_left(guild_id: int, user_id: int):
    await _run("UPDATE guild_members SET left_at_utc=? WHERE guild_id=? AND user_id=?",
               (utcnow_iso(), guild_id, user_id))


async def set_member_nick(guild_id: int, user_id: int, nickname):
    await _run("""
        INSERT INTO guild_members (guild_id, user_id, nickname) VALUES (?, ?, ?)
        ON CONFLICT(guild_id, user_id) DO UPDATE SET nickname=excluded.nickname
    """, (guild_id, user_id, nickname))


async def get_memberships(user_id: int, guild_id: int):
    if guild_id is None:
        raise ValueError("A server is required for membership history")
    return await _all("SELECT * FROM guild_members WHERE user_id=? AND guild_id=? ORDER BY joined_at_utc", (user_id, guild_id))


# ============================================================ message archive
async def log_message(row: dict):
    await _run("""
        INSERT OR IGNORE INTO message_log
            (message_id, guild_id, channel_id, author_id, author_name, content, reply_to_id,
             created_at_utc, content_hash)
        VALUES (:message_id, :guild_id, :channel_id, :author_id, :author_name, :content, :reply_to_id,
                :created_at_utc, :content_hash)
    """, row)


async def archive_message(profile: dict, row: dict):
    """Store one incoming message and its public profile in one transaction."""
    await run_transaction([
        (_PROFILE_UPSERT, {**profile, "now": utcnow_iso()}),
        ("""INSERT OR IGNORE INTO message_log
         (message_id,guild_id,channel_id,author_id,author_name,content,reply_to_id,created_at_utc,content_hash)
         VALUES (:message_id,:guild_id,:channel_id,:author_id,:author_name,:content,:reply_to_id,:created_at_utc,:content_hash)""", row),
    ])


async def add_attachment(row: dict):
    await _run("""
        INSERT INTO attachments (message_id, guild_id, channel_id, author_id, filename, url,
                                 mirror_url, sha256, size, content_type)
        VALUES (:message_id, :guild_id, :channel_id, :author_id, :filename, :url,
                :mirror_url, :sha256, :size, :content_type)
    """, row)


async def get_message(message_id: int):
    return await _one("SELECT * FROM message_log WHERE message_id=?", (message_id,))


async def get_messages(ids: list):
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    return await _all(f"SELECT * FROM message_log WHERE message_id IN ({marks})", tuple(ids))


async def get_attachments(message_id: int):
    return await _all("SELECT * FROM attachments WHERE message_id=?", (message_id,))


async def mark_deleted(ids: list):
    now = utcnow_iso()
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        marks = ",".join("?" * len(chunk))
        await _run(f"UPDATE message_log SET deleted=1, deleted_at_utc=? WHERE message_id IN ({marks})",
                   (now, *chunk))


async def log_edit(message_id: int, old: str, new: str, new_hash):
    now = utcnow_iso()
    await run_transaction([
        ("INSERT INTO message_edits (message_id, old_content, new_content, edited_at_utc) VALUES (?,?,?,?)", (message_id, old, new, now)),
        ("UPDATE message_log SET content=?, content_hash=?, edited=1 WHERE message_id=?", (new, new_hash, message_id)),
    ])


async def recent_messages_by_author(author_id: int, since_iso: str, limit: int = 200, guild_id=None):
    scope = " AND guild_id=?" if guild_id is not None else ""
    args = (author_id, since_iso) + ((guild_id,) if guild_id is not None else ()) + (limit,)
    return await _all("SELECT * FROM message_log WHERE author_id=? AND deleted=0 AND created_at_utc>=?" + scope +
                      " ORDER BY created_at_utc DESC LIMIT ?", args)


async def count_messages(author_id: int, guild_id: int) -> int:
    r = await _one("SELECT COUNT(*) AS n FROM message_log WHERE author_id=? AND guild_id=?", (author_id, guild_id))
    return r["n"] if r else 0


async def add_purge_audit(guild_id: int, invoker_id: int, command: str, count: int):
    await _run("INSERT INTO purge_audit (guild_id, invoker_id, command, deleted_count, ran_at_utc) VALUES (?,?,?,?,?)",
               (guild_id, invoker_id, command[:500], count, utcnow_iso()))


# ============================================================ compromised-account protection
async def flag_user(user_id: int, flagged_by: int, guild_id: int, reason: str, expires_iso):
    await _run("""
        INSERT INTO compromised_users (user_id, flagged_by, source_guild_id, reason, flagged_at_utc, expires_at_utc, active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(user_id) DO UPDATE SET flagged_by=excluded.flagged_by, source_guild_id=excluded.source_guild_id,
            reason=excluded.reason, flagged_at_utc=excluded.flagged_at_utc,
            expires_at_utc=excluded.expires_at_utc, active=1
    """, (user_id, flagged_by, guild_id, reason, utcnow_iso(), expires_iso))
    await _run("DELETE FROM compromised_exempt WHERE user_id=?", (user_id,))


async def get_active_flags():
    return await _all("SELECT * FROM compromised_users WHERE active=1")


async def get_flag(user_id: int):
    return await _one("SELECT * FROM compromised_users WHERE user_id=? AND active=1", (user_id,))


async def clear_flag(user_id: int):
    await _run("UPDATE compromised_users SET active=0 WHERE user_id=?", (user_id,))
    await _run("DELETE FROM compromised_fingerprints WHERE user_id=?", (user_id,))
    await _run("DELETE FROM compromised_exempt WHERE user_id=?", (user_id,))


async def expire_flags() -> list:
    now = utcnow_iso()
    rows = await _all("SELECT user_id FROM compromised_users WHERE active=1 AND expires_at_utc IS NOT NULL AND expires_at_utc<=?", (now,))
    ids = [r["user_id"] for r in rows]
    for uid in ids:
        await clear_flag(uid)
    return ids


async def add_fingerprint(user_id: int, content_hash, domains: str, shas: str, sample: str):
    await _run("""INSERT INTO compromised_fingerprints (user_id, content_hash, domains, attachment_shas, sample, created_at_utc)
                  VALUES (?,?,?,?,?,?)""", (user_id, content_hash, domains, shas, sample, utcnow_iso()))


async def get_fingerprints():
    return await _all("""SELECT f.* FROM compromised_fingerprints f
                         JOIN compromised_users u ON u.user_id=f.user_id AND u.active=1""")


async def add_exempt(guild_id: int, user_id: int):
    await _run("INSERT OR IGNORE INTO compromised_exempt (guild_id, user_id) VALUES (?,?)", (guild_id, user_id))


async def get_exempts():
    return await _all("SELECT guild_id, user_id FROM compromised_exempt")


async def set_protection(guild_id: int, on: bool):
    await _run("""INSERT INTO guild_protection (guild_id, network_protection) VALUES (?, ?)
                  ON CONFLICT(guild_id) DO UPDATE SET network_protection=excluded.network_protection""",
               (guild_id, 1 if on else 0))


async def get_protection_off() -> set:
    rows = await _all("SELECT guild_id FROM guild_protection WHERE network_protection=0")
    return {r["guild_id"] for r in rows}


# ============================================================ alt-account heuristics
def _canon(s) -> str:
    return re.sub(r"[^a-z]", "", (s or "").lower())


async def alt_signals(user_id: int, guild_id: int) -> dict:
    """Weak investigation clues from this guild only; never automatic punishment."""
    me = await _one("SELECT p.* FROM user_profiles p JOIN guild_members m USING(user_id) WHERE p.user_id=? AND m.guild_id=?", (user_id, guild_id))
    if not me:
        return {}
    out = {}
    def add(uid, reason, weight):
        if uid != user_id and all(r != reason for r, _ in out.get(uid, [])):
            out.setdefault(uid, []).append((reason, weight))
    peers = await _all("SELECT p.* FROM user_profiles p JOIN guild_members m USING(user_id) WHERE m.guild_id=? AND p.user_id!=? LIMIT 5000", (guild_id, user_id))
    mine = {_canon(me["username"]), _canon(me["global_name"])} - {""}
    for peer in peers:
        if me["avatar_hash"] and peer["avatar_hash"] == me["avatar_hash"]:
            add(peer["user_id"], "same avatar (may be a common image)", 20)
        theirs = {_canon(peer["username"]), _canon(peer["global_name"])} - {""}
        best = max((SequenceMatcher(None, x, y).ratio() for x in mine for y in theirs
                    if min(len(x), len(y)) >= 4 and abs(len(x)-len(y)) <= 3), default=0)
        if best >= .85:
            add(peer["user_id"], "similar name", 15)
    for row in await _all("""SELECT DISTINCT b.author_id AS uid FROM attachments a
        JOIN attachments b ON b.sha256=a.sha256 AND b.author_id!=a.author_id AND b.guild_id=a.guild_id
        WHERE a.guild_id=? AND a.author_id=? AND a.sha256 IS NOT NULL LIMIT 100""", (guild_id, user_id)):
        add(row["uid"], "shared an identical file in this server", 10)
    for row in await _all("""SELECT b.user_id AS uid FROM guild_members a JOIN guild_members b
        ON b.guild_id=a.guild_id AND b.user_id!=a.user_id AND b.invite_code=a.invite_code
        WHERE a.guild_id=? AND a.user_id=? AND a.invite_code IS NOT NULL
        AND ABS(julianday(a.joined_at_utc)-julianday(b.joined_at_utc))*86400<1800 LIMIT 100""", (guild_id, user_id)):
        add(row["uid"], "same invite within 30 minutes in this server", 10)
    return out


# ============================================================ log routing / options
async def get_routes() -> dict:
    rows = await _all("SELECT guild_id, category, channel_id FROM guild_log_routes")
    return {(r["guild_id"], r["category"]): r["channel_id"] for r in rows}


async def set_route(guild_id: int, category: str, channel_id: int):
    """channel_id = 0 disables that category."""
    await _run("""INSERT INTO guild_log_routes (guild_id, category, channel_id) VALUES (?,?,?)
                  ON CONFLICT(guild_id, category) DO UPDATE SET channel_id=excluded.channel_id""",
               (guild_id, category, channel_id))


async def delete_route(guild_id: int, category: str):
    await _run("DELETE FROM guild_log_routes WHERE guild_id=? AND category=?", (guild_id, category))


async def get_mirror_off() -> set:
    rows = await _all("SELECT guild_id FROM guild_options WHERE media_mirror=0")
    return {r["guild_id"] for r in rows}


async def set_media_mirror(guild_id: int, on: bool):
    await _run("""INSERT INTO guild_options (guild_id, media_mirror) VALUES (?, ?)
                  ON CONFLICT(guild_id) DO UPDATE SET media_mirror=excluded.media_mirror""",
               (guild_id, 1 if on else 0))


async def set_attachment_mirror(message_id: int, original_url: str, mirror_url: str):
    await _run("UPDATE attachments SET mirror_url=? WHERE message_id=? AND url=?",
               (mirror_url, message_id, original_url))


async def get_avatar_mirror(user_id: int, avatar_hash: str):
    r = await _one("SELECT mirror_url FROM avatar_mirrors WHERE user_id=? AND avatar_hash=?", (user_id, avatar_hash))
    return r["mirror_url"] if r else None


async def add_avatar_mirror(user_id: int, avatar_hash: str, url: str):
    await _run("INSERT OR REPLACE INTO avatar_mirrors (user_id, avatar_hash, mirror_url, saved_at_utc) VALUES (?,?,?,?)",
               (user_id, avatar_hash, url, utcnow_iso()))


# ============================================================ audit events (staff actions)
async def add_audit_event(guild_id: int, action: str, actor_id, target_id, summary: str):
    await _run("""INSERT INTO audit_events (guild_id, action, actor_id, target_id, summary, created_at_utc)
                  VALUES (?,?,?,?,?,?)""", (guild_id, action, actor_id, target_id, summary[:500], utcnow_iso()))


async def get_audit_events(user_id: int, guild_id: int, limit: int = 6):
    return await _all("""SELECT * FROM audit_events WHERE guild_id=? AND (target_id=? OR actor_id=?)
                         ORDER BY id DESC LIMIT ?""", (guild_id, user_id, user_id, limit))


# ============================================================ retention / erasure
PRIVACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS guild_privacy (
    guild_id INTEGER PRIMARY KEY, archive_enabled INTEGER NOT NULL DEFAULT 1,
    retention_days INTEGER NOT NULL DEFAULT 30
);
CREATE TABLE IF NOT EXISTS archive_exclusions (
    guild_id INTEGER NOT NULL, channel_id INTEGER NOT NULL, PRIMARY KEY(guild_id,channel_id)
);
CREATE TABLE IF NOT EXISTS capture_optouts (
    guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id)
);
CREATE INDEX IF NOT EXISTS idx_alarms_due ON alarms(paused,time_utc);
CREATE INDEX IF NOT EXISTS idx_msg_retention ON message_log(guild_id,created_at_utc);
CREATE INDEX IF NOT EXISTS idx_history_scope ON profile_history(guild_id,user_id,changed_at_utc);
CREATE INDEX IF NOT EXISTS idx_edits_message ON message_edits(message_id);
"""


def default_retention():
    value = int(os.getenv("RETENTION_DAYS", "30") or "30")
    if not 1 <= value <= 3650:
        raise ValueError("RETENTION_DAYS must be between 1 and 3650; indefinite retention is disabled")
    return value


async def get_privacy(guild_id):
    return await _one("SELECT * FROM guild_privacy WHERE guild_id=?", (guild_id,)) or {
        "guild_id": guild_id, "archive_enabled": 1, "retention_days": default_retention()}


async def set_privacy(guild_id, *, archive_enabled=None, retention_days=None):
    current = await get_privacy(guild_id)
    if retention_days is not None and not 1 <= retention_days <= 3650:
        raise ValueError("Retention must be 1–3650 days")
    await _run("""INSERT INTO guild_privacy VALUES (?,?,?) ON CONFLICT(guild_id) DO UPDATE SET
        archive_enabled=excluded.archive_enabled,retention_days=excluded.retention_days""",
        (guild_id, current["archive_enabled"] if archive_enabled is None else int(archive_enabled),
         current["retention_days"] if retention_days is None else retention_days))


async def get_privacy_guilds():
    return await _all("SELECT * FROM guild_privacy")


async def set_archive_exclusion(guild_id, channel_id, excluded):
    if excluded:
        await _run("INSERT OR IGNORE INTO archive_exclusions VALUES (?,?)", (guild_id, channel_id))
    else:
        await _run("DELETE FROM archive_exclusions WHERE guild_id=? AND channel_id=?", (guild_id, channel_id))


async def set_capture_optout(user_id, guild_id, enabled):
    if enabled:
        await _run("INSERT OR IGNORE INTO capture_optouts VALUES (?,?)", (guild_id or 0, user_id))
    else:
        await _run("DELETE FROM capture_optouts WHERE guild_id=? AND user_id=?", (guild_id or 0, user_id))


async def should_archive(guild_id, channel_id=None, user_id=None, parent_ids=()):
    if not (await get_privacy(guild_id))["archive_enabled"]:
        return False
    if user_id is not None and await _one("SELECT 1 FROM capture_optouts WHERE user_id=? AND guild_id IN (0,?)", (user_id, guild_id)):
        return False
    ids = [i for i in (channel_id, *parent_ids) if i is not None]
    if ids:
        marks = ",".join("?" for _ in ids)
        if await _one(f"SELECT 1 FROM archive_exclusions WHERE guild_id=? AND channel_id IN ({marks})", (guild_id, *ids)):
            return False
    return True


async def prune_messages(older_than_iso, guild_id=None):
    scope, args = (" AND guild_id=?", (older_than_iso, guild_id)) if guild_id is not None else ("", (older_than_iso,))
    selector = "SELECT message_id FROM message_log WHERE created_at_utc<?" + scope
    count = await _one("SELECT COUNT(*) AS n FROM message_log WHERE created_at_utc<?" + scope, args)
    await run_transaction([
        ("DELETE FROM message_edits WHERE message_id IN (" + selector + ")", args),
        ("DELETE FROM attachments WHERE message_id IN (" + selector + ")", args),
        ("DELETE FROM message_log WHERE created_at_utc<?" + scope, args),
    ])
    return count["n"]


async def prune_history(older_than_iso, guild_id):
    await run_transaction([
        ("DELETE FROM profile_history WHERE guild_id=? AND changed_at_utc<?", (guild_id, older_than_iso)),
        ("DELETE FROM audit_events WHERE guild_id=? AND created_at_utc<?", (guild_id, older_than_iso)),
        ("DELETE FROM purge_audit WHERE guild_id=? AND ran_at_utc<?", (guild_id, older_than_iso)),
        ("DELETE FROM guild_members WHERE guild_id=? AND left_at_utc<?", (guild_id, older_than_iso)),
    ])


async def _table_columns():
    tables = await _all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    result = {}
    for table in tables:
        name = table["name"]
        if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name):
            result[name] = {r["name"] for r in await _all(f'PRAGMA table_info("{name}")')}
    return result


async def forget_user(user_id: int, guild_id=None, *, include_security=False):
    """Erase archived/personal data within the requested scope. Active security is separate.

    Global erasure is reserved for the person's own private request. A guild caller
    never erases preferences, another guild's rows, or shared public profile state.
    Failed mirror deletions retain guardian_media pointers so they can be retried.
    """
    columns = await _table_columns()
    scope = " AND guild_id=?" if guild_id is not None else ""
    args = (user_id, guild_id) if guild_id is not None else (user_id,)
    statements = [("DELETE FROM message_edits WHERE message_id IN (SELECT message_id FROM message_log WHERE author_id=?" + scope + ")", args)]
    owned = {
        "attachments": "author_id", "message_log": "author_id", "profile_history": "user_id",
        "guild_members": "user_id", "alarms": "user_id", "alarm_delivery_history": "user_id",
        "community_event_subscriptions": "user_id", "community_event_delivery": "user_id",
        "community_event_preferences": "user_id",
    }
    for table, column in owned.items():
        if table not in columns:
            continue
        if guild_id is not None and "guild_id" not in columns[table]:
            continue
        statements.append((f"DELETE FROM {table} WHERE {column}=?" + scope, args))
    if "community_events" in columns:
        event_selector = "SELECT id FROM community_events WHERE creator_id=?" + scope
        if "community_event_delivery" in columns:
            statements.append(("UPDATE community_event_delivery SET state='cancelled' WHERE event_id IN (" + event_selector + ")", args))
        statements.append(("UPDATE community_events SET state='cancelled' WHERE creator_id=?" + scope, args))
    # Audit and report records include other people's actions; remove the requested
    # person's references and their free text without destroying others' cases.
    for table, fields in {
        "audit_events": ("actor_id", "target_id"), "purge_audit": ("invoker_id",),
        "community_events": ("creator_id",),
        "guild_members": ("inviter_id",),
    }.items():
        if table not in columns or (guild_id is not None and "guild_id" not in columns[table]):
            continue
        for field in fields:
            if field not in columns[table]:
                continue
            redact = [f"{field}=0"]
            for textcol in ("summary", "command", "reason", "evidence", "note", "detail", "details", "resolution", "title"):
                if textcol in columns[table]:
                    redact.append(f"{textcol}='[erased]'")
            statements.append((f"UPDATE {table} SET " + ",".join(redact) + f" WHERE {field}=?" + scope, args))
    if guild_id is None:
        for table in ("user_profiles", "avatar_mirrors", "user_timezones", "alarm_user_preferences"):
            if table in columns:
                statements.append((f"DELETE FROM {table} WHERE user_id=?", (user_id,)))
        # Legacy global security references are no longer used for enforcement.
        for table in ("compromised_users", "compromised_fingerprints", "compromised_exempt"):
            if table in columns:
                statements.append((f"DELETE FROM {table} WHERE user_id=?", (user_id,)))
        statements.append(("UPDATE compromised_users SET flagged_by=0 WHERE flagged_by=?", (user_id,)))
    if include_security:
        for table in ("guardian_flags", "guardian_patterns", "guardian_exempt"):
            if table in columns and "user_id" in columns[table]:
                security_scope = " AND source_guild_id=?" if guild_id is not None else ""
                statements.append((f"DELETE FROM {table} WHERE user_id=?" + security_scope, args))
    await run_transaction(statements)


async def export_user(user_id, guild_id=None):
    """Only return this person's records; never staff notes or others' reports."""
    columns = await _table_columns()
    result = {}
    personal = {
        "message_log": "author_id", "attachments": "author_id", "profile_history": "user_id",
        "guild_members": "user_id", "alarms": "user_id", "alarm_delivery_history": "user_id",
        "community_event_subscriptions": "user_id", "community_event_delivery": "user_id",
        "community_event_preferences": "user_id",
    }
    if guild_id is None:
        personal.update(user_profiles="user_id", user_timezones="user_id", alarm_user_preferences="user_id")
    for table, column in personal.items():
        if table not in columns or (guild_id is not None and "guild_id" not in columns[table]):
            continue
        scope = " AND guild_id=?" if guild_id is not None else ""
        args = (user_id,guild_id) if guild_id is not None else (user_id,)
        result[table] = await _all(f"SELECT * FROM {table} WHERE {column}=?" + scope, args)
        if table == "guild_members":
            for row in result[table]:
                row.pop("inviter_id", None)
                row.pop("invite_code", None)
    result["scope"] = "all your personal data" if guild_id is None else f"server {guild_id}"
    result["notice"] = "Staff reports, private notes, and active security evidence are not exposed by this export."
    return result
