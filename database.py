"""
database.py - SQLite storage for the alarm bot and the Guardian cog.

The SQLite file is the ONLY thing this bot writes to disk. Attachments and avatars are mirrored into
Discord log channels; the database stores text and the mirror URLs.
"""
import os
import re
import shutil
import sqlite3
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from pathlib import Path

import aiosqlite
import pytz

# ============================================================ configuration
# Absolute path, independent of the launch directory. On hosts with an ephemeral disk
# (Railway, Heroku, ...) point DATA_DIR at a persistent volume or settings are lost on restart.
DATA_DIR = Path(os.getenv("DATA_DIR") or (Path(__file__).resolve().parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "alarm_bot.db")

# one-time migration of a database created by older versions (relative path)
for _old in (Path("alarm_bot.db"), Path(__file__).resolve().parent / "alarm_bot.db"):
    if _old.exists() and not Path(DB_PATH).exists():
        shutil.copy2(_old, DB_PATH)
        break

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
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.executescript(SCHEMA)
        for stmt in MIGRATIONS:
            try:
                await db.execute(stmt)
            except sqlite3.OperationalError:
                pass                                  # column already exists
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
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        cur = await db.execute(sql, params)
        await db.commit()
        return cur.rowcount


async def _insert(sql, params=()) -> int:
    """Execute an INSERT; returns the new row id."""
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        cur = await db.execute(sql, params)
        await db.commit()
        return cur.lastrowid


async def _all(sql, params=()) -> list:
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]


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


async def get_history(user_id: int, guild_id=None, limit: int = 15):
    """guild_id=None -> everything; otherwise global rows + that guild's nickname rows."""
    if guild_id is None:
        return await _all("SELECT * FROM profile_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
                          (user_id, limit))
    return await _all("""SELECT * FROM profile_history WHERE user_id=? AND (guild_id IS NULL OR guild_id=?)
                         ORDER BY id DESC LIMIT ?""", (user_id, guild_id, limit))


async def sync_profiles(profiles: list, members: list) -> int:
    """Startup bulk sync. Records history for anything that changed while the bot was offline."""
    now = utcnow_iso()
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
                    hist.append((p["user_id"], None, kind, o[key], p[key], None, now))
        for m in members:
            k = (m["guild_id"], m["user_id"])
            if k in old_nick and old_nick[k] != m["nickname"]:
                hist.append((m["user_id"], m["guild_id"], "nickname", old_nick[k], m["nickname"], None, now))

        await db.executemany(_PROFILE_UPSERT, [{**p, "now": now} for p in profiles])
        await db.executemany("""
            INSERT INTO guild_members (guild_id, user_id, nickname, joined_at_utc, left_at_utc)
            VALUES (:guild_id, :user_id, :nickname, :joined, NULL)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET nickname=excluded.nickname, left_at_utc=NULL
        """, members)
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


async def get_memberships(user_id: int):
    return await _all("SELECT * FROM guild_members WHERE user_id=? ORDER BY joined_at_utc", (user_id,))


# ============================================================ message archive
async def log_message(row: dict):
    await _run("""
        INSERT OR IGNORE INTO message_log
            (message_id, guild_id, channel_id, author_id, author_name, content, reply_to_id,
             created_at_utc, content_hash)
        VALUES (:message_id, :guild_id, :channel_id, :author_id, :author_name, :content, :reply_to_id,
                :created_at_utc, :content_hash)
    """, row)


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
    await _run("INSERT INTO message_edits (message_id, old_content, new_content, edited_at_utc) VALUES (?,?,?,?)",
               (message_id, old, new, now))
    await _run("UPDATE message_log SET content=?, content_hash=?, edited=1 WHERE message_id=?",
               (new, new_hash, message_id))


async def recent_messages_by_author(author_id: int, since_iso: str, limit: int = 200):
    return await _all("""SELECT * FROM message_log WHERE author_id=? AND deleted=0 AND created_at_utc>=?
                         ORDER BY created_at_utc DESC LIMIT ?""", (author_id, since_iso, limit))


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


async def alt_signals(user_id: int) -> dict:
    """Returns {other_user_id: [(reason, weight), ...]}. Heuristics only - never proof."""
    out: dict = {}

    def add(uid, reason, w):
        if uid == user_id:
            return
        if all(r != reason for r, _ in out.get(uid, [])):
            out.setdefault(uid, []).append((reason, w))

    me = await get_profile(user_id)
    if not me:
        return out

    if me["avatar_hash"]:
        for r in await _all("SELECT user_id FROM user_profiles WHERE avatar_hash=? AND user_id!=? LIMIT 50",
                            (me["avatar_hash"], user_id)):
            add(r["user_id"], "same current avatar image", 40)

    for r in await _all("""
        SELECT DISTINCT h2.user_id AS uid FROM profile_history h1
        JOIN profile_history h2 ON h2.kind='avatar' AND h2.user_id!=h1.user_id
                               AND h2.new_value IS NOT NULL AND h2.new_value=h1.new_value
        WHERE h1.kind='avatar' AND h1.user_id=? AND h1.new_value IS NOT NULL LIMIT 50""", (user_id,)):
        add(r["uid"], "has used the same avatar image in the past", 30)

    for r in await _all("""
        SELECT DISTINCT a2.author_id AS uid FROM attachments a1
        JOIN attachments a2 ON a2.sha256=a1.sha256 AND a2.author_id!=a1.author_id
        WHERE a1.author_id=? AND a1.sha256 IS NOT NULL LIMIT 50""", (user_id,)):
        add(r["uid"], "uploaded an identical file", 15)

    for r in await _all("""
        SELECT DISTINCT g2.user_id AS uid FROM guild_members g1
        JOIN guild_members g2 ON g2.guild_id=g1.guild_id AND g2.user_id!=g1.user_id
                             AND g2.invite_code=g1.invite_code
                             AND ABS(julianday(g2.joined_at_utc)-julianday(g1.joined_at_utc))*86400 < 1800
        WHERE g1.user_id=? AND g1.invite_code IS NOT NULL LIMIT 100""", (user_id,)):
        add(r["uid"], "joined a server with the same invite within 30 min", 10)

    if me["account_created_utc"]:
        for r in await _all("""SELECT user_id AS uid FROM user_profiles WHERE user_id!=?
                               AND ABS(julianday(account_created_utc)-julianday(?))*86400 < 300 LIMIT 100""",
                            (user_id, me["account_created_utc"])):
            add(r["uid"], "account created within 5 min of this one", 10)

    mine = {_canon(me["username"]), _canon(me["global_name"])} - {""}
    if mine:
        for r in await _all("SELECT user_id, username, global_name FROM user_profiles WHERE user_id!=?", (user_id,)):
            theirs = {_canon(r["username"]), _canon(r["global_name"])} - {""}
            best = 0.0
            for a in mine:
                for b in theirs:
                    if min(len(a), len(b)) < 4 or abs(len(a) - len(b)) > 3:
                        continue
                    if a == b:
                        best = 1.0
                    else:
                        sm = SequenceMatcher(None, a, b)
                        if sm.quick_ratio() >= 0.85:
                            best = max(best, sm.ratio())
            if best == 1.0:
                add(r["user_id"], "same name (ignoring digits/symbols)", 25)
            elif best >= 0.85:
                add(r["user_id"], "very similar name", 15)
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
async def prune_messages(older_than_iso: str) -> int:
    await _run("""DELETE FROM message_edits WHERE message_id IN
                  (SELECT message_id FROM message_log WHERE created_at_utc<?)""", (older_than_iso,))
    await _run("""DELETE FROM attachments WHERE message_id IN
                  (SELECT message_id FROM message_log WHERE created_at_utc<?)""", (older_than_iso,))
    return await _run("DELETE FROM message_log WHERE created_at_utc<?", (older_than_iso,))


async def forget_user(user_id: int):
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("""DELETE FROM message_edits WHERE message_id IN
                            (SELECT message_id FROM message_log WHERE author_id=?)""", (user_id,))
        for table, col in (("attachments", "author_id"), ("message_log", "author_id"),
                           ("user_profiles", "user_id"), ("profile_history", "user_id"),
                           ("guild_members", "user_id"), ("avatar_mirrors", "user_id"),
                           ("audit_events", "target_id"), ("compromised_users", "user_id"),
                           ("compromised_fingerprints", "user_id"), ("compromised_exempt", "user_id")):
            await db.execute(f"DELETE FROM {table} WHERE {col}=?", (user_id,))
        await db.commit()
