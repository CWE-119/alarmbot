"""Verified SQLite backups and an explicit, offline restore command."""
import argparse
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def verify_backup(path):
    source = Path(path).resolve()
    if not source.is_file():
        raise ValueError(f"Database does not exist: {source}")
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as connection:
        checks = [row[0] for row in connection.execute("PRAGMA integrity_check")]
        if checks != ["ok"]:
            raise ValueError("Database integrity check failed: " + "; ".join(checks[:5]))
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"alarms", "user_timezones"} <= tables:
            raise ValueError("This file is not an Alarm Bot database")
    return True


def backup_database(source_path, destination_path):
    source, destination = Path(source_path).resolve(), Path(destination_path).resolve()
    if source == destination:
        raise ValueError("Backup destination must differ from the live database")
    if not source.is_file():
        raise ValueError("Source database does not exist")
    if destination.exists():
        raise ValueError("Destination already exists; choose a new backup filename")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=".alarm-backup-", suffix=".db", dir=destination.parent)
    os.close(descriptor)
    try:
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as source_db, closing(sqlite3.connect(temp_name)) as target_db:
            source_db.backup(target_db)
        verify_backup(temp_name)
        os.replace(temp_name, destination)
        os.chmod(destination, 0o600)
    finally:
        Path(temp_name).unlink(missing_ok=True)
    return destination


def restore_database(backup_path, destination_path, *, bot_stopped=False, replace=False):
    if not bot_stopped:
        raise ValueError("Stop the bot and explicitly pass --bot-stopped before restoring")
    source, destination = Path(backup_path).resolve(), Path(destination_path).resolve()
    verify_backup(source)
    if source == destination:
        raise ValueError("Backup and restore destination must differ")
    if destination.exists() and not replace:
        raise ValueError("Destination exists; --replace is required")
    for suffix in ("-wal", "-shm"):
        if Path(str(destination) + suffix).exists():
            raise ValueError("SQLite sidecar files remain. Shut down all database connections before restoring")
    previous = None
    if destination.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        previous = destination.with_name(f"pre-restore-{stamp}.db")
        backup_database(destination, previous)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=".alarm-restore-", suffix=".db", dir=destination.parent)
    os.close(descriptor)
    Path(temp_name).unlink()
    try:
        backup_database(source, temp_name)
        os.replace(temp_name, destination)
    finally:
        Path(temp_name).unlink(missing_ok=True)
    return previous


def automated_backup(database_path, backup_dir, keep=7):
    folder = Path(backup_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    result = backup_database(database_path, folder / f"alarm-auto-{stamp}.db")
    for old in sorted(folder.glob("alarm-auto-*.db"), reverse=True)[keep:]:
        old.unlink()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    backup = sub.add_parser("backup", help="Create and verify a consistent online backup")
    backup.add_argument("destination")
    backup.add_argument("--database")
    verify = sub.add_parser("verify", help="Verify backup integrity without modifying it")
    verify.add_argument("backup")
    restore = sub.add_parser("restore", help="Restore while the bot is stopped; preserve current DB as pre-restore backup")
    restore.add_argument("backup")
    restore.add_argument("--database")
    restore.add_argument("--replace", action="store_true")
    restore.add_argument("--bot-stopped", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            verify_backup(args.backup)
            print("Backup integrity verified.")
            return
        import database as db
        path = args.database or db.DB_PATH
        if args.command == "backup":
            print(f"Verified backup saved to {backup_database(path, args.destination)}")
        else:
            previous = restore_database(args.backup, path, bot_stopped=args.bot_stopped, replace=args.replace)
            print(f"Restored database to {path}. Previous database backup: {previous or 'not applicable'}")
    except (ValueError, sqlite3.Error, OSError) as exc:
        parser.exit(1, f"Maintenance failed: {exc}\n")


if __name__ == "__main__":
    main()
