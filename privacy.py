"""Server-scoped archive controls and private personal-data tools."""
import gzip
import asyncio
import io
import json
import logging
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands
from discord.ext import commands, tasks

import database as db
import maintenance

log = logging.getLogger(__name__)


class EraseConfirmation(discord.ui.View):
    def __init__(self, cog, user_id, guild_id):
        super().__init__(timeout=60)
        self.cog, self.user_id, self.guild_id = cog, user_id, guild_id

    async def interaction_check(self, interaction):
        return interaction.user.id == self.user_id and interaction.guild_id == self.guild_id

    @discord.ui.button(label="Erase my stored data", style=discord.ButtonStyle.danger)
    async def erase(self, interaction, button):
        await interaction.response.defer(ephemeral=True)
        result = await self.cog.erase(self.user_id, self.guild_id)
        await interaction.edit_original_response(content=result, view=None)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction, button):
        await interaction.response.edit_message(content="Data deletion cancelled.", view=None)
        self.stop()


class Privacy(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.last_retention_error = None
        self.last_backup_error = None
        self.last_backup_at = None

    async def cog_load(self):
        self.retention.start()
        self.backups.start()

    async def cog_unload(self):
        pending = [loop.get_task() for loop in (self.retention, self.backups) if loop.get_task()]
        self.retention.cancel()
        self.backups.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    @commands.hybrid_command(name="privacysettings", description="View or change this server's archive and retention settings")
    @commands.guild_only()
    @commands.has_guild_permissions(administrator=True)
    @app_commands.default_permissions(administrator=True)
    async def privacysettings(self, ctx, archive: bool | None = None, retention_days: int | None = None):
        if archive is not None or retention_days is not None:
            try:
                await db.set_privacy(ctx.guild.id, archive_enabled=archive, retention_days=retention_days)
            except ValueError as exc:
                return await ctx.send(str(exc), ephemeral=True)
        settings = await db.get_privacy(ctx.guild.id)
        exclusions = await db._all("SELECT channel_id FROM archive_exclusions WHERE guild_id=?", (ctx.guild.id,))
        await ctx.send(
            f"Archive: **{'on' if settings['archive_enabled'] else 'off'}**\n"
            f"Retention: **{settings['retention_days']} days**\n"
            f"Excluded channels/categories: {', '.join('<#'+str(r['channel_id'])+'>' for r in exclusions) or 'none'}\n"
            "Security checks and member reports work independently of routine archiving. "
            "Turning archiving off prevents future collection; retention removes older records.", ephemeral=True)

    @commands.hybrid_command(name="archiveexclude", description="Exclude a channel or category from future archiving")
    @commands.guild_only()
    @commands.has_guild_permissions(administrator=True)
    @app_commands.default_permissions(administrator=True)
    async def archiveexclude(self, ctx, channel: discord.TextChannel | discord.CategoryChannel, excluded: bool = True):
        if channel.guild.id != ctx.guild.id:
            return await ctx.send("Choose a channel in this server.", ephemeral=True)
        await db.set_archive_exclusion(ctx.guild.id, channel.id, excluded)
        await ctx.send(f"{channel.mention}: {'excluded from' if excluded else 'included in'} future archiving.", ephemeral=True)

    @app_commands.command(name="dataoptout", description="Control storage of your routine messages and profile history")
    async def dataoptout(self, interaction: discord.Interaction, enabled: bool = True):
        await db.set_capture_optout(interaction.user.id, interaction.guild_id, enabled)
        scope = "this server" if interaction.guild_id else "all servers"
        await interaction.response.send_message(
            f"Routine archive opt-out {'enabled' if enabled else 'disabled'} for {scope}. "
            "Use /forgetme to erase previously archived data. Security evidence and reports are managed separately.", ephemeral=True)

    @app_commands.command(name="dataexport", description="Privately download your stored personal data")
    @app_commands.checks.cooldown(1, 120, key=lambda i: i.user.id)
    async def dataexport(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        data = await db.export_user(interaction.user.id, interaction.guild_id)
        payload = gzip.compress(json.dumps(data, indent=2, ensure_ascii=False).encode())
        limit = min(getattr(interaction.guild, "filesize_limit", 8 * 1024 * 1024), 8 * 1024 * 1024)
        if len(payload) > limit:
            return await interaction.followup.send("Your export exceeds the attachment limit. Export separately in each server or ask its administrator for an offline export.", ephemeral=True)
        await interaction.followup.send("Your private data export (JSON, gzip compressed).",
            file=discord.File(io.BytesIO(payload), filename="my-data.json.gz"), ephemeral=True)

    @app_commands.command(name="forgetme", description="Erase your stored personal data after confirmation")
    @app_commands.checks.cooldown(1, 120, key=lambda i: i.user.id)
    async def forgetme(self, interaction: discord.Interaction):
        scope = "this server" if interaction.guild_id else "all servers and your private reminders"
        await interaction.response.send_message(
            f"Erase your archived data and reminders in **{scope}**, and opt out of future routine archiving? "
            "This cannot be undone. Active security restrictions remain until staff clear them or they expire. "
            "Staff incident evidence follows separate incident retention. "
            "Tracked mirrored copies will be deleted where the bot has access; old copies without IDs may need staff cleanup.",
            view=EraseConfirmation(self, interaction.user.id, interaction.guild_id), ephemeral=True)

    async def erase(self, user_id, guild_id):
        await db.set_capture_optout(user_id, guild_id, True)
        guardian = self.bot.get_cog("Guardian")
        mirrors = await guardian.erase_user_media(user_id, guild_id=guild_id) if guardian else {"removed": 0, "failed": 0}
        await db.forget_user(user_id, guild_id=guild_id)
        return (f"Your stored personal data was erased {'in this server' if guild_id else 'across servers'}. "
                f"Mirrored copies removed: {mirrors['removed']}; pending cleanup: {mirrors['failed']}. "
                "Routine archive opt-out is enabled. Active security records, staff incident evidence, and separately retained backups are not cleared by this command.")

    @tasks.loop(hours=6)
    async def retention(self):
        try:
            guild_ids = {g.id for g in self.bot.guilds}
            for row in await db._all("SELECT DISTINCT guild_id FROM message_log UNION SELECT guild_id FROM guild_privacy UNION SELECT DISTINCT guild_id FROM profile_history"):
                if row["guild_id"]:
                    guild_ids.add(row["guild_id"])
            guardian = self.bot.get_cog("Guardian")
            for gid in guild_ids:
                settings = await db.get_privacy(gid)
                cutoff = (datetime.now(timezone.utc) - timedelta(days=settings["retention_days"])).isoformat()
                if guardian:
                    await guardian.prune_media(cutoff, guild_id=gid)
                await db.prune_messages(cutoff, guild_id=gid)
                await db.prune_history(cutoff, gid)
                columns = await db._table_columns()
                # Completed reminders and incident history follow the same local retention.
                for table, date_col in (("alarm_delivery_history", "occurred_at_utc"),):
                    if table in columns and {"guild_id", date_col} <= columns[table]:
                        await db._run(f"DELETE FROM {table} WHERE guild_id=? AND {date_col}<?", (gid, cutoff))
                if "community_cases" in columns:
                    import community_store
                    await community_store.prune(settings["retention_days"], guild_id=gid)
            # Legacy unscoped historical rows must not be retained indefinitely.
            cutoff = (datetime.now(timezone.utc)-timedelta(days=db.default_retention())).isoformat()
            await db.run_transaction([
                ("DELETE FROM profile_history WHERE guild_id IS NULL AND changed_at_utc<?", (cutoff,)),
                ("DELETE FROM avatar_mirrors WHERE saved_at_utc<?", (cutoff,)),
                ("DELETE FROM user_profiles WHERE last_seen_utc<? AND user_id NOT IN (SELECT user_id FROM guild_members WHERE left_at_utc IS NULL)", (cutoff,)),
            ])
            self.last_retention_error = None
        except Exception as exc:
            self.last_retention_error = type(exc).__name__
            log.exception("Archive retention failed")

    @retention.before_loop
    async def before_retention(self):
        await self.bot.wait_until_ready()

    @tasks.loop(hours=24)
    async def backups(self):
        if os.getenv("AUTO_BACKUP", "true").lower() not in {"1", "true", "yes"}:
            return
        try:
            destination = os.getenv("BACKUP_DIR") or str(Path(db.DB_PATH).parent / "backups")
            await asyncio.to_thread(maintenance.automated_backup, db.DB_PATH, destination, 7)
            self.last_backup_at = datetime.now(timezone.utc).isoformat()
            self.last_backup_error = None
        except Exception as exc:
            self.last_backup_error = type(exc).__name__
            log.exception("Automatic database backup failed")

    @backups.before_loop
    async def before_backups(self):
        await self.bot.wait_until_ready()


async def setup(bot):
    await bot.add_cog(Privacy(bot))
