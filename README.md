# Alarm Bot

Alarms + a full logging / moderation / protection suite. Settings live in SQLite, so you set things up
**once** and they survive restarts.

| File | What it is |
|---|---|
| `main.py` | bot start-up, `!help`, alarms and timezones |
| `guardian.py` | logging, audit-log attribution, scoped delete, alt tracking, compromised-account protection |
| `database.py` | all storage (SQLite). The `.db` file is the only thing written to disk |

## Setup
1. `pip install -r requirements.txt`, copy `.env.example` to `.env`, add your token.
2. Developer Portal → Bot → enable **Server Members Intent** and **Message Content Intent**.
3. Invite the bot with: *View Channels, Send Messages, Embed Links, Attach Files, Read Message History,
   Manage Messages, Moderate Members, View Audit Log, Manage Server* (Manage Server = invite tracking).
4. `python main.py`, then in each server run **`!setuplogs #logs`** once. Check with **`!logstatus`**.

## Where logs go
`!setuplogs` sends everything to one channel. Split it with `!setlog <category> #channel` (or `off` / `default`):

`messages` · `media` · `members` · `voice` · `roles` · `moderation` · `server` · `security`

## How it works
- **Attachments and avatars are never saved to disk.** They're read into memory and re-posted into the `media`
  log channel; the database keeps the link. If someone deletes that copy in your log channel, it's gone.
- **"Who did it" comes from Discord's audit log** (needs *View Audit Log*): roles given/removed, permission
  changes, bans, kicks, timeouts, channel/role/invite edits. Voice moves and disconnects are matched to audit
  entries by timing, so in rare overlaps they can name the wrong moderator. Repeated deletes by a moderator
  are merged by Discord, so later ones can show as "author / a bot".
- **Compromised accounts:** reply to the bad message with `!compromised`. It removes their last hour of
  messages, times them out in every server the bot shares with them, and blocks the same text/links/images.
  The flagging server clears it everywhere with `!uncompromised`; other servers can opt out with `!protect off`.
- **Alt detection** (`!userinfo`) is heuristic: shared avatar image, similar names, identical files, same invite,
  similar account age. IP / MAC addresses are not available to bots and are not collected.

## Privacy
The bot stores message text, names, nicknames, avatars, join/invite data and staff actions. Tell your members,
and check Discord's Developer Policy. `RETENTION_DAYS` auto-prunes message text; `!forgetuser <id>` (owner)
erases a person from the database.

Run `!help` in Discord for the full command list (it only shows what *you* can use).
