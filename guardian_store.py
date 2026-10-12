"""Guild-scoped security policy and bot-owned Discord artifact bookkeeping.

Legacy global compromised flags are intentionally not imported: administrators
must choose trusted sources before another server can affect their members.
"""
import json

import aiosqlite

import database as db

SCHEMA = """
CREATE TABLE IF NOT EXISTS guardian_settings (
    guild_id INTEGER PRIMARY KEY, network_enabled INTEGER NOT NULL DEFAULT 0,
    report_only INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS guardian_trust (
    guild_id INTEGER NOT NULL, source_guild_id INTEGER NOT NULL,
    PRIMARY KEY (guild_id, source_guild_id)
);
CREATE TABLE IF NOT EXISTS guardian_flags (
    source_guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    flagged_by INTEGER NOT NULL, reason TEXT NOT NULL, expires_at_utc TEXT,
    flagged_at_utc TEXT NOT NULL, PRIMARY KEY (source_guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS guardian_exempt (
    guild_id INTEGER NOT NULL, source_guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    PRIMARY KEY (guild_id, source_guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS guardian_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT, source_guild_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL, content_hash TEXT, urls TEXT NOT NULL DEFAULT '[]',
    attachment_shas TEXT NOT NULL DEFAULT '[]', sample TEXT NOT NULL DEFAULT '',
    evidence_message_id INTEGER, created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS guardian_pattern_exempt (
    guild_id INTEGER NOT NULL, pattern_id INTEGER NOT NULL,
    PRIMARY KEY (guild_id, pattern_id)
);
CREATE TABLE IF NOT EXISTS guardian_timeouts (
    guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, source_guild_id INTEGER NOT NULL,
    previous_until TEXT, applied_until TEXT NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS guardian_media (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL, original_message_id INTEGER,
    channel_id INTEGER NOT NULL, message_id INTEGER NOT NULL,
    kind TEXT NOT NULL, asset_key TEXT, created_at_utc TEXT NOT NULL,
    UNIQUE(channel_id, message_id)
);
CREATE INDEX IF NOT EXISTS guardian_media_origin ON guardian_media(guild_id,original_message_id);
"""


async def init():
    async with aiosqlite.connect(db.DB_PATH, timeout=30) as connection:
        await connection.executescript(SCHEMA)
        await connection.commit()


async def snapshot():
    return {
        "settings": await db._all("SELECT * FROM guardian_settings"),
        "trust": await db._all("SELECT * FROM guardian_trust"),
        "flags": await db._all("SELECT * FROM guardian_flags WHERE expires_at_utc IS NULL OR expires_at_utc>?", (db.utcnow_iso(),)),
        "exempts": await db._all("SELECT * FROM guardian_exempt"),
        "patterns": await db._all("""SELECT p.* FROM guardian_patterns p JOIN guardian_flags f
            ON f.source_guild_id=p.source_guild_id AND f.user_id=p.user_id
            WHERE f.expires_at_utc IS NULL OR f.expires_at_utc>?""", (db.utcnow_iso(),)),
        "pattern_exempts": await db._all("SELECT * FROM guardian_pattern_exempt"),
    }


async def set_option(guild_id, option, enabled):
    if option not in {"network_enabled", "report_only"}:
        raise ValueError("Unknown security option")
    await db._run(f"INSERT INTO guardian_settings(guild_id,{option}) VALUES (?,?) "
                  f"ON CONFLICT(guild_id) DO UPDATE SET {option}=excluded.{option}", (guild_id, int(enabled)))


async def trust(guild_id, source_guild_id, enabled):
    if enabled:
        await db._run("INSERT OR IGNORE INTO guardian_trust VALUES (?,?)", (guild_id, source_guild_id))
    else:
        await db._run("DELETE FROM guardian_trust WHERE guild_id=? AND source_guild_id=?", (guild_id, source_guild_id))


async def flag(source_guild_id, user_id, actor_id, reason, expires):
    await db._run("""INSERT INTO guardian_flags VALUES (?,?,?,?,?,?)
        ON CONFLICT(source_guild_id,user_id) DO UPDATE SET flagged_by=excluded.flagged_by,
        reason=excluded.reason,expires_at_utc=excluded.expires_at_utc,flagged_at_utc=excluded.flagged_at_utc""",
        (source_guild_id, user_id, actor_id, reason, expires, db.utcnow_iso()))
    # Other servers' exemptions are deliberate local policy and survive reflags.


async def clear_flag(source_guild_id, user_id):
    await db._run("DELETE FROM guardian_flags WHERE source_guild_id=? AND user_id=?", (source_guild_id, user_id))
    await db._run("DELETE FROM guardian_pattern_exempt WHERE pattern_id IN (SELECT id FROM guardian_patterns WHERE source_guild_id=? AND user_id=?)", (source_guild_id, user_id))
    await db._run("DELETE FROM guardian_patterns WHERE source_guild_id=? AND user_id=?", (source_guild_id, user_id))


async def expire_flags():
    for flag_row in await db._all("SELECT * FROM guardian_flags WHERE expires_at_utc IS NOT NULL AND expires_at_utc<=?", (db.utcnow_iso(),)):
        await clear_flag(flag_row["source_guild_id"], flag_row["user_id"])


async def exempt(guild_id, source_guild_id, user_id):
    await db._run("INSERT OR IGNORE INTO guardian_exempt VALUES (?,?,?)", (guild_id, source_guild_id, user_id))


async def add_pattern(source_guild_id, user_id, content_hash, urls, shas, sample, evidence_id):
    return await db._insert("""INSERT INTO guardian_patterns
        (source_guild_id,user_id,content_hash,urls,attachment_shas,sample,evidence_message_id,created_at_utc)
        VALUES (?,?,?,?,?,?,?,?)""", (source_guild_id, user_id, content_hash, json.dumps(sorted(urls)),
                                    json.dumps(sorted(shas)), sample[:500], evidence_id, db.utcnow_iso()))


async def remove_pattern(guild_id, pattern_id):
    row = await db._one("SELECT * FROM guardian_patterns WHERE id=?", (pattern_id,))
    if row is None:
        return False
    if row["source_guild_id"] == guild_id:
        await db._run("DELETE FROM guardian_patterns WHERE id=? AND source_guild_id=?", (pattern_id, guild_id))
        await db._run("DELETE FROM guardian_pattern_exempt WHERE pattern_id=?", (pattern_id,))
    else:
        await db._run("INSERT OR IGNORE INTO guardian_pattern_exempt VALUES (?,?)", (guild_id, pattern_id))
    return True


async def timeout_record(guild_id, user_id):
    return await db._one("SELECT * FROM guardian_timeouts WHERE guild_id=? AND user_id=?", (guild_id, user_id))


async def save_timeout(guild_id, user_id, source_guild_id, previous_until, applied_until):
    await db._run("""INSERT INTO guardian_timeouts VALUES (?,?,?,?,?)
        ON CONFLICT(guild_id,user_id) DO UPDATE SET source_guild_id=excluded.source_guild_id,
        previous_until=excluded.previous_until,applied_until=excluded.applied_until""",
        (guild_id, user_id, source_guild_id, previous_until, applied_until))


async def remove_timeout(guild_id, user_id):
    await db._run("DELETE FROM guardian_timeouts WHERE guild_id=? AND user_id=?", (guild_id, user_id))


async def add_media(guild_id, author_id, original_message_id, channel_id, message_id, kind, asset_key=None):
    await db._run("""INSERT OR IGNORE INTO guardian_media
        (guild_id,author_id,original_message_id,channel_id,message_id,kind,asset_key,created_at_utc)
        VALUES (?,?,?,?,?,?,?,?)""", (guild_id, author_id, original_message_id, channel_id, message_id, kind, asset_key, db.utcnow_iso()))


async def list_media(guild_id=None, author_id=None, before=None, original_message_id=None, kind=None, asset_key=None):
    filters, params = [], []
    for column, value in (("guild_id", guild_id), ("author_id", author_id), ("original_message_id", original_message_id), ("kind", kind), ("asset_key", asset_key)):
        if value is not None:
            filters.append(f"{column}=?")
            params.append(value)
    if before is not None:
        filters.append("created_at_utc<?")
        params.append(before)
    query = "SELECT * FROM guardian_media" + (" WHERE " + " AND ".join(filters) if filters else "")
    return await db._all(query, tuple(params))


async def remove_media(row_id):
    await db._run("DELETE FROM guardian_media WHERE id=?", (row_id,))
