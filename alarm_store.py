"""Durable reminder state and delivery leases. No network or import-time writes."""
import uuid
from datetime import timedelta

import database as db
from scheduling import anchor_for, as_utc, first_occurrence, iso, next_occurrence, normalize_repeat, utcnow, validate_message

MAX_ACTIVE = 50
MAX_ATTEMPTS = 6
COLUMNS = {
    "guild_id": "INTEGER", "scope_known": "INTEGER NOT NULL DEFAULT 0",
    "destination": "TEXT NOT NULL DEFAULT 'channel'", "state": "TEXT NOT NULL DEFAULT 'active'",
    "schedule_anchor": "TEXT", "until_utc": "TEXT", "snoozed_until_utc": "TEXT",
    "next_attempt_utc": "TEXT", "attempts": "INTEGER NOT NULL DEFAULT 0", "last_error": "TEXT",
    "delivered_at_utc": "TEXT", "lease_token": "TEXT", "lease_until_utc": "TEXT",
    "version": "INTEGER NOT NULL DEFAULT 0",
}


async def init_db():
    columns = {row["name"] for row in await db._all("PRAGMA table_info(alarms)")}
    for name, declaration in COLUMNS.items():
        if name not in columns:
            await db._run(f"ALTER TABLE alarms ADD COLUMN {name} {declaration}")
    await db._run("CREATE INDEX IF NOT EXISTS idx_alarm_due ON alarms(state,paused,time_utc)")
    await db._run("CREATE INDEX IF NOT EXISTS idx_alarm_owner ON alarms(user_id,guild_id)")
    await db._run("""CREATE TABLE IF NOT EXISTS alarm_delivery_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, alarm_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        guild_id INTEGER, outcome TEXT NOT NULL, detail TEXT, occurred_at_utc TEXT NOT NULL)""")
    await db._run("CREATE INDEX IF NOT EXISTS idx_alarm_history ON alarm_delivery_history(user_id,guild_id,id)")
    await db._run("""CREATE TABLE IF NOT EXISTS alarm_user_preferences (
        user_id INTEGER PRIMARY KEY, quiet_start TEXT, quiet_end TEXT)""")
    for alarm in await db._all("SELECT id,time_utc,timezone FROM alarms WHERE schedule_anchor IS NULL"):
        try:
            anchor = anchor_for(as_utc(alarm["time_utc"]), alarm["timezone"])
            await db._run("UPDATE alarms SET schedule_anchor=? WHERE id=?", (anchor, alarm["id"]))
        except (ValueError, OverflowError):
            await db._run("UPDATE alarms SET state='failed',last_error='Invalid legacy schedule; edit this reminder.' WHERE id=?", (alarm["id"],))


def scope(user_id, guild_id):
    # A private DM can manage all reminders owned by its author. Guild requests cannot.
    if guild_id is None:
        return "user_id=?", (user_id,)
    return "user_id=? AND guild_id=? AND scope_known=1", (user_id, guild_id)


async def get(alarm_id, user_id=None, guild_id=None):
    if user_id is None:
        return await db._one("SELECT * FROM alarms WHERE id=?", (alarm_id,))
    clause, params = scope(user_id, guild_id)
    return await db._one(f"SELECT * FROM alarms WHERE id=? AND {clause}", (alarm_id, *params))


async def list_for(user_id, guild_id, page=1):
    clause, params = scope(user_id, guild_id)
    total = await db._one(f"SELECT COUNT(*) AS n FROM alarms WHERE {clause}", params)
    rows = await db._all(f"""SELECT * FROM alarms WHERE {clause}
        ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'failed' THEN 1 ELSE 2 END,
        COALESCE(snoozed_until_utc,time_utc),id LIMIT 5 OFFSET ?""", (*params, (page-1)*5))
    return rows, total["n"]


async def history(user_id, guild_id, page=1):
    clause, params = scope(user_id, guild_id)
    # History has no scope_known flag: only records whose resolved guild matches are visible.
    clause = clause.replace(" AND scope_known=1", "")
    return await db._all(f"SELECT * FROM alarm_delivery_history WHERE {clause} ORDER BY id DESC LIMIT 10 OFFSET ?", (*params, (page-1)*10))


async def add(user_id, guild_id, channel_id, destination, when, tz_name, repeat, message, until=None):
    repeat = normalize_repeat(repeat)
    when = first_occurrence(when, tz_name, repeat)
    if until and as_utc(until) <= when:
        raise ValueError("The end date must come after the first reminder.")
    message = validate_message(message)
    alarm_id = await db._insert("""INSERT INTO alarms
        (user_id,guild_id,scope_known,channel_id,destination,time_utc,timezone,repeat,message,
         schedule_anchor,until_utc,created_at_utc)
        SELECT ?,?,1,?,?,?,?,?,?,?,?,? WHERE
        (SELECT COUNT(*) FROM alarms WHERE user_id=? AND state NOT IN ('done','delivered')) < ?
        AND (SELECT COUNT(*) FROM alarms WHERE user_id=?) < 200""",
        (user_id,guild_id,channel_id,destination,iso(when),tz_name,repeat,message,
         anchor_for(when,tz_name),iso(until) if until else None,iso(utcnow()),user_id,MAX_ACTIVE,user_id))
    if not alarm_id:
        raise ValueError(f"You may keep {MAX_ACTIVE} active reminders and 200 total. Delete old reminders first.")
    return await get(alarm_id, user_id, guild_id)


async def mutate(alarm, updates):
    allowed = set(COLUMNS) | {"time_utc", "timezone", "repeat", "message", "paused", "channel_id"}
    if not updates or not set(updates) <= allowed:
        raise ValueError("Invalid reminder update.")
    assignments = ",".join(f"{key}=?" for key in updates)
    changed = await db._run(f"""UPDATE alarms SET {assignments},version=version+1,
        lease_token=NULL,lease_until_utc=NULL WHERE id=? AND user_id=? AND version=?""",
        (*updates.values(), alarm["id"], alarm["user_id"], alarm["version"]))
    if not changed:
        raise ValueError("This reminder changed while you were editing. Please try again.")
    return await get(alarm["id"])


async def edit(alarm, when, tz_name, repeat, message, until=None):
    repeat = normalize_repeat(repeat)
    when = first_occurrence(when, tz_name, repeat)
    if until and as_utc(until) <= when:
        raise ValueError("The end date must come after the first reminder.")
    return await mutate(alarm, dict(time_utc=iso(when), timezone=tz_name, repeat=repeat,
        message=validate_message(message), schedule_anchor=anchor_for(when,tz_name),
        until_utc=iso(until) if until else None, snoozed_until_utc=None, next_attempt_utc=None,
        attempts=0,last_error=None,state="active",paused=0))


async def snooze(alarm, delta):
    when = utcnow() + delta
    if alarm["until_utc"] and when >= as_utc(alarm["until_utc"]):
        raise ValueError("That snooze would pass this reminder's end date. Edit the end date first.")
    return await mutate(alarm, dict(snoozed_until_utc=iso(when),next_attempt_utc=None,
        state="active",paused=0,attempts=0,last_error=None))


async def done(alarm):
    if alarm["repeat"]:
        next_time = next_occurrence(alarm["schedule_anchor"],alarm["timezone"],alarm["repeat"],utcnow())
        ended = bool(alarm["until_utc"] and next_time >= as_utc(alarm["until_utc"]))
        return await mutate(alarm, dict(time_utc=iso(next_time),snoozed_until_utc=None,
            next_attempt_utc=None,state="done" if ended else "active",attempts=0,last_error=None))
    return await mutate(alarm, dict(state="done",snoozed_until_utc=None,next_attempt_utc=None))


async def delete(alarm):
    changed = await db._run("DELETE FROM alarms WHERE id=? AND user_id=? AND version=?", (alarm["id"],alarm["user_id"],alarm["version"]))
    if not changed:
        raise ValueError("This reminder changed; please try again.")


async def pending_legacy(user_id=None):
    return await db._all("SELECT * FROM alarms WHERE scope_known=0" + (" AND user_id=?" if user_id is not None else "") + " LIMIT 200", (user_id,) if user_id is not None else ())


async def resolve_scope(alarm, guild_id, destination):
    await db._run("UPDATE alarms SET guild_id=?,scope_known=1,destination=? WHERE id=? AND scope_known=0", (guild_id,destination,alarm["id"]))


async def preferences(user_id):
    return await db._one("SELECT * FROM alarm_user_preferences WHERE user_id=?", (user_id,)) or {}


async def set_quiet(user_id, start, end):
    await db._run("""INSERT INTO alarm_user_preferences (user_id,quiet_start,quiet_end) VALUES (?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET quiet_start=excluded.quiet_start,quiet_end=excluded.quiet_end""", (user_id,start,end))


async def due(now=None):
    now = iso(now or utcnow())
    # Lease expiry recovers a worker crash. Delivery is at least once, not exactly once.
    return await db._all("""SELECT * FROM alarms WHERE paused=0 AND
        (state='active' OR (state='sending' AND lease_until_utc<=?))
        AND COALESCE(next_attempt_utc,snoozed_until_utc,time_utc)<=?
        ORDER BY COALESCE(next_attempt_utc,snoozed_until_utc,time_utc) LIMIT 100""", (now,now))


async def claim(alarm, now=None):
    now = now or utcnow()
    token = uuid.uuid4().hex
    changed = await db._run("""UPDATE alarms SET state='sending',lease_token=?,lease_until_utc=?
        WHERE id=? AND version=? AND paused=0 AND
        (state='active' OR (state='sending' AND lease_until_utc<=?))
        AND COALESCE(next_attempt_utc,snoozed_until_utc,time_utc)<=?""",
        (token,iso(now+timedelta(minutes=5)),alarm["id"],alarm["version"],iso(now),iso(now)))
    return await db._one("SELECT * FROM alarms WHERE id=? AND lease_token=?", (alarm["id"],token)) if changed else None


async def defer(alarm, when):
    await db._run("""UPDATE alarms SET state='active',next_attempt_utc=?,lease_token=NULL,lease_until_utc=NULL
        WHERE id=? AND lease_token=?""", (iso(when),alarm["id"],alarm["lease_token"]))


async def record(alarm, outcome, detail=""):
    await db._run("""INSERT INTO alarm_delivery_history
        (alarm_id,user_id,guild_id,outcome,detail,occurred_at_utc) VALUES (?,?,?,?,?,?)""",
        (alarm["id"],alarm["user_id"],alarm["guild_id"],outcome,detail[:300],iso(utcnow())))


async def delivered(alarm, now=None):
    now = now or utcnow()
    next_time = next_occurrence(alarm["schedule_anchor"],alarm["timezone"],alarm["repeat"],now) if alarm["repeat"] else None
    ended = next_time is None or bool(alarm["until_utc"] and next_time >= as_utc(alarm["until_utc"]))
    changed = await db._run("""UPDATE alarms SET state=?,time_utc=?,delivered_at_utc=?,
        snoozed_until_utc=NULL,next_attempt_utc=NULL,attempts=0,last_error=NULL,
        lease_token=NULL,lease_until_utc=NULL,version=version+1 WHERE id=? AND lease_token=?""",
        ("delivered" if ended else "active",iso(next_time) if next_time else alarm["time_utc"],iso(now),alarm["id"],alarm["lease_token"]))
    if changed:
        await record(alarm,"delivered")
    return bool(changed)


async def failed(alarm, error, permanent=False, now=None):
    now = now or utcnow()
    attempts = alarm["attempts"] + 1
    stopped = permanent or attempts >= MAX_ATTEMPTS
    retry = None if stopped else iso(now+timedelta(seconds=min(3600,30 * 2 ** (attempts-1))))
    changed = await db._run("""UPDATE alarms SET state=?,attempts=?,last_error=?,next_attempt_utc=?,
        lease_token=NULL,lease_until_utc=NULL,version=version+1 WHERE id=? AND lease_token=?""",
        ("failed" if stopped else "active",attempts,str(error)[:300],retry,alarm["id"],alarm["lease_token"]))
    if changed:
        await record(alarm,"failed" if stopped else "retry",str(error))
    return stopped and bool(changed)


async def cleanup():
    cutoff = iso(utcnow()-timedelta(days=30))
    await db._run("DELETE FROM alarm_delivery_history WHERE guild_id IS NULL AND occurred_at_utc<?", (iso(utcnow()-timedelta(days=90)),))
    await db._run("DELETE FROM alarms WHERE state IN ('delivered','done') AND COALESCE(delivered_at_utc,created_at_utc)<?", (cutoff,))
