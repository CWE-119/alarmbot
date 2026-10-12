# Repository security and deployment notes

The SSH private key, legacy SQLite database, and legacy JSON data are excluded from new commits. Their local copies remain available to the operator. This does not remove earlier Git history or revoke an SSH key on a server.

If this repository or key has been shared, replace the corresponding authorized key on every host that trusts it, verify the replacement login works, then remove the old authorized key. Do not delete your only working SSH credential before verifying replacement access. The bot does not need an SSH private key at runtime.

Repository history cleanup changes commit IDs and requires coordinating with anyone using the repository. Make a restricted backup first; use a history-cleaning tool to remove `ssh-key-2025-04-12.key`, `alarm_bot.db`, and `alarm_data.json` from the shared history, then follow your host's instructions for purging cached copies. Key rotation is required even after history cleanup if the key was exposed. No server credentials were rotated and no shared history was rewritten by this change.

The bot's token belongs in `.env` or the host's secret manager. Runtime data and backups belong on a persistent volume with access restricted to the bot operator. Daily automatic snapshots are kept for seven runs; use storage encryption and off-host copies if you require protection from disk loss. Restoring a snapshot can restore previously erased data; retain archive opt-out requests and reapply erasures after recovery.

Server administrators control only their server's ordinary moderation, investigation, archive settings, reports, and events. A bot operator still controls the process and database; server isolation is enforced by the application, not encryption against its operator.

Cross-server protection requires the receiving administrator to enable network protection and trust the sending server. Only compromised-account protection and spam/raid security alerts use that route. Heuristic spam/raid alerts alone do not authorize automatic punishments in another server. Review trust relationships and pattern evidence before enabling them.

Private reports and staff notes stay out of member data exports. Archive opt-out and self-service erasure do not cancel active security restrictions or remove staff incident evidence. These are separately managed through moderation commands and finite incident retention. Mirrored Discord messages created by older versions did not store message IDs and may require manual removal.
