# Alarm Bot + Guardian

Discord reminders, server-specific moderation and private reports, voluntary event reminders, and explicitly trusted security alerts. State is stored in SQLite on a persistent volume.

**Server boundaries:** a server's users and moderators cannot inspect or change another server's ordinary records, reports, settings, events, or moderation. Members manage only their own alarms. Private DM alarm management can access that same member's reminders across servers. Spam/raid alerts and compromised-account protection are the only security exceptions, and receiving servers must explicitly enable the network and trust a source server.

**Install and start**

Python 3.11 or newer is required. From this directory:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp -n env.example .env
# Edit .env and set DISCORD_TOKEN. Use a persistent DATA_DIR when hosting.
.venv/bin/python main.py
```

Alternatively, `uv sync --locked` installs the versions in `uv.lock`; run with `uv run python main.py`. Dependency versions are defined in `pyproject.toml`; `requirements.txt` installs that project.

In Discord's Developer Portal, enable **Server Members Intent** and **Message Content Intent**. Invite with the `bot` and `applications.commands` scopes. Grant only the capabilities you use: View Channels, Send Messages, Embed Links, Attach Files, Read Message History; Manage Messages and Moderate Members for moderation; View Audit Log for attribution; Manage Server for invite tracking. The bot's role must be above members it moderates. Administrator permission is not required for the bot.

In each server, run `!setuplogs #staff-logs`, then `/health`. Keep archive and report channels accessible only to appropriate staff. Existing prefix alarm commands remain supported. Slash commands are registered at startup when `SYNC_COMMANDS=true`; Discord may take time to display global commands.

The existing `alarm_bot.db` beside the source is migrated on first startup if the configured destination does not exist. Files are not copied or created just by importing the modules. Existing global compromised flags are not automatically promoted into the new trusted network; staff must reflag confirmed incidents under the new policy.

**Alarms**

- `/settimezone` accepts timezone names with autocomplete, for example `Asia/Dhaka`.
- `/alarm create` sets a reminder with a time, message, repeat rule, and delivery destination. `/alarm edit`, `/alarm list`, `/alarm history`, and `/alarm status` manage it privately.
- Repeat rules: `once`, `daily`, `weekly`, `weekdays`, `monthly`, or selected days such as `mon,wed,fri`. Optional end dates stop recurring reminders.
- `/alarm destination` selects a permitted channel or DM. Channel permissions and current membership are checked at delivery as well as setup.
- `/alarm quiet` delays delivery during your chosen quiet hours. Use `off` to disable.
- Reminder buttons provide **Snooze 10m**, **Done**, and **Reschedule**. Snoozing moves just that occurrence, preserving the recurring schedule. Completed one-time reminders remain available for snoozing/history until cleanup.
- Right-click a message and select **Remind me** to create a reminder linked to it.

Prefix examples:

```text
!settimezone Asia/Dhaka
!setalarm tomorrow 9am weekdays | Start work
!setalarm in 2h | Check the oven
!setalarm 18:00 mon,wed,fri | Study group
!editalarm 12 tomorrow 10am once | One-time replacement
!listalarms
!snooze 12 10m
!pausealarm 12
!resumealarm 12
!deletealarm 12
```

The scheduler retains failed reminders, retries temporary delivery problems with backoff, and shows failures in history. It sends at most one catch-up notification after downtime before advancing a recurring reminder to a future occurrence. Missing permissions or destinations produce an actionable failure instead of silently deleting the reminder. A failed destination can be changed before resuming.

Schedules keep their intended local clock time across daylight-saving changes. A nonexistent local time moves forward by the DST gap; a repeated local time uses the first occurrence. Monthly reminders clamp to the last day of a short month and return to the original day in later months. Reminder text is limited to 1,200 characters; each member may keep 50 active and 200 total reminders. Alarm lists are paginated. Only the intended recipient can be pinged by reminder text.

Delivery uses persisted leases and is **at least once**: a process crash after Discord accepts a message but before SQLite records success can cause one duplicate. Run one bot process per database; this is not a distributed scheduling service.

**Moderation and trusted security**

Ordinary purge and investigation commands always operate inside the current server. Bot-owner status does not bypass another server's command permissions. Audit attribution includes the server ID and reports uncertainty rather than claiming an unverified actor. Possible alternate-account clues are local and are not evidence sufficient for automatic punishment.

```text
!alarmbot -d -u @user -t 1h -c #general
!userinfo @user
!compromised @user 24h confirmed account compromise
!uncompromised @user
!flagged
```

Replying to a confirmed malicious message with `!compromised` also creates a reviewable pattern from that evidence. It does not learn from every message in the user's last hour, and it does not block an entire domain just because one URL appeared. Checks run on new and edited messages. Pattern review/removal and report-only security mode are available to staff.

To accept security information from another server, a receiving administrator must configure both:

```text
!protect on
/trustserver server_id:123456789012345678 state:on
```

Only explicitly trusted sources can trigger cross-server compromised-account protection or send spam/raid alerts. Use `!protect off` or remove trust to stop accepting that source. Local exemptions survive another server reflagging the same account. Clearing protection restores only a timeout the bot still owns; it preserves longer or changed timeouts imposed by moderators. Security report-only mode records matches without imposing new restrictions.

Use `/patterns` to inspect applicable confirmed patterns and `/removepattern` to remove a local pattern or suppress a received one in your server. `/securitymode mode:report` records matches without new punishment; `mode:enforce` enables enforcement.

**Reports, raids, and community events**

- A server manager first runs `/reportsetup` with a private staff channel. Members then use `/report` or the **Report message** context menu. Responses are private. Reports become local case IDs with evidence and staff action history.
- Staff use `/cases`, `/case`, `/caseaction`, and `/resolve`; involved members can submit `/appeal`. An appeal requires a different reviewing moderator. A case ID from another server does not grant access.
- `/communitysecurity` configures message floods, mention floods, and bursts of joins. Defaults are disabled until configured. Alert mode is available before enabling local deletion. Heuristic spam/raid alerts never directly punish members in another server.
- `/event` creates a scheduled community reminder using an ISO time such as `2026-10-18T18:00+06:00`; `/events` lists events and `/eventcancel` cancels an authorized event. Members explicitly subscribe/unsubscribe using buttons. Events are limited to 80 subscribers, five active events per creator, and thirty per server.
- `/eventdelivery` selects an opted-in member's delivery preference. No event pings everyone or an unsolicited role. Event subscriptions and delivery permissions stay within that event's server.
- `/health` reports database health, permissions, queues, scheduler status, and backup/retention status for staff.

**Archiving and privacy**

`!setuplogs #channel` sets a default log destination. `!setlog <category> <#channel|off|default>` routes `messages`, `media`, `members`, `voice`, `roles`, `moderation`, `server`, or `security`. `!logstatus` shows routing. `!mediamirror off` disables new media copies. A disabled log destination controls output; use the archive controls below to stop routine collection.

- `/privacysettings` controls this server's routine archive and retention, from 1 to 3,650 days. The default is **30 days**; indefinite retention is disabled.
- `/archiveexclude` excludes a channel/category and its applicable children from future routine archiving.
- `/dataoptout` disables routine message/profile collection for yourself in the current server. In a DM it applies globally.
- `/dataexport` provides a private compressed JSON export of your personal data in the current server; use it in a DM for all your personal records. It does not expose confidential reports or staff notes.
- `/forgetme` asks you to confirm erasure of your archived data and reminders, then enables archive opt-out. In a server it affects only that server; in a DM it covers your own records globally.
- `!forgetuser <id>` is a server administrator's archive cleanup command, limited to that server.

Active security restrictions and private incident evidence are managed separately from self-service archive erasure, preventing someone from clearing a punishment by deleting their profile. Resolved incidents and completed event data follow server retention. Database backups have their own retention and can contain earlier copies until they expire.

Attachments and avatar images are never written as local media files. A bounded worker queue downloads limited bytes and mirrors eligible media into the configured staff channel. The database records the mirrored message/channel IDs, so the bot can fetch fresh signed URLs and delete tracked copies during cleanup. A deleted log message is not recoverable from SQLite. Older copies without message IDs require manual cleanup; inaccessible copies remain tracked for retries. Tell members what you archive before enabling these features.

**Backups and recovery**

A verified SQLite snapshot is made daily by default (`AUTO_BACKUP=true`); the last seven automatic snapshots are retained in `DATA_DIR/backups`, or `BACKUP_DIR`. Store this folder on persistent storage and copy backups off-host when disk-loss recovery matters.

```sh
.venv/bin/python maintenance.py backup /safe/path/manual-backup.db
.venv/bin/python maintenance.py verify /safe/path/manual-backup.db
# Stop the bot before restore. A verified pre-restore copy is preserved.
.venv/bin/python maintenance.py restore /safe/path/manual-backup.db --replace --bot-stopped
```

Restoration refuses to run while SQLite sidecar files remain. Keep all bot processes stopped, verify the restored database, then restart. An old snapshot may restore previously erased data; reapply recent erasure/opt-out requests. See [SECURITY.md](SECURITY.md) for the tracked-key cleanup and host-side actions that still require the operator.

**Development checks**

```sh
.venv/bin/python -m pip install '.[test]'
BOT_TESTING=1 .venv/bin/python -m pytest -q
```

Tests use synthetic temporary databases and mocked Discord objects. They cover server boundaries, scheduling/DST, delivery recovery, moderation safeguards, privacy, and backup/restore. They do not log into Discord. Test mode prevents copying the legacy production database.

Source layout: `main.py` provides alarm commands and startup; `scheduling.py` calculates calendar occurrences; `alarm_store.py` stores delivery state; `guardian.py`/`guardian_store.py` implement moderation and security; `community.py`/`community_store.py` implement reports and events; `privacy.py` handles privacy and automatic maintenance; `database.py` provides shared storage; `maintenance.py` provides backup/restore tooling.
