import discord
from discord.ext import commands, tasks
from datetime import datetime, timedelta
from dateutil import parser
import pytz
import os
from dotenv import load_dotenv
from flask import Flask
from threading import Thread
import time
import requests
import logging
from database import *

# Load environment variables
load_dotenv()

# Initialize bot with required intents
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
intents.members = True
intents.voice_states = True
intents.guilds = True
intents.invites = True

bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# Custom Help Command
@bot.command(name='alarmhelp')
async def custom_help(ctx):
    help_embed = discord.Embed(
        title="Alarm Bot Commands Help",
        description="All times are handled in your specified timezone (defaults to UTC if not set)",
        color=discord.Color.blue()
    )

    basic_commands = {
        '!alarmhelp': 'Shows this help message with all available commands',
        '!settimezone <timezone>': 'Sets your timezone (e.g., America/New_York, Asia/Tokyo)\nUses standard timezone format (Continent/City)',
        '!gettimezone': 'Shows your currently set timezone',
        '!setalarm <time> [repeat] [message]': 'Sets a new alarm\n• Time: Supports natural language (3pm, 15:30, tomorrow 9am)\n• Repeat (optional): "daily" or "weekly"\n• Message (optional): Custom alarm message',
        '!listalarms': 'Lists all your active alarms\nShows ID, time, repeat status, and message',
        '!deletealarm <id>': 'Deletes a specific alarm by ID'
    }

    admin_commands = {
        '!setlogchannel <channel>': 'Sets the logging channel for the server\nRequires administrator permissions',
        '!toggledeletelog': 'Toggles message delete logging\nRequires administrator permissions'
    }

    # Add basic commands
    help_embed.add_field(name="Basic Commands", value="‎", inline=False)
    for cmd, desc in basic_commands.items():
        help_embed.add_field(name=cmd, value=desc, inline=False)

    # Add admin commands
    help_embed.add_field(name="Admin Commands", value="‎", inline=False)
    for cmd, desc in admin_commands.items():
        help_embed.add_field(name=cmd, value=desc, inline=False)

    # Add features section
    features = """
• Message delete logging (when enabled)
• Voice channel join/leave logging
• Recurring alarms (daily/weekly)
• Timezone support
• Natural language time parsing
"""
    help_embed.add_field(name="Features", value=features, inline=False)

    await ctx.send(embed=help_embed)

# Timezone Commands
@bot.command(name='settimezone')
async def set_timezone(ctx, timezone: str):
    try:
        pytz.timezone(timezone)
        await set_user_timezone(ctx.author.id, timezone)
        await ctx.send(f'(⊙_⊙)？ Timezone set to {timezone}')
    except pytz.UnknownTimeZoneError:
        await ctx.send('~_~ Invalid timezone. Use format like "Continent/City"')

@bot.command(name='gettimezone')
async def get_timezone(ctx):
    timezone = await get_user_timezone(ctx.author.id)
    await ctx.send(f'(￣┰￣*) Your timezone: {timezone}')

# Alarm Commands
@bot.command(name='setalarm')
async def set_alarm(ctx, time_str: str, repeat: str = None, *, message: str = "Alarm!"):
    try:
        user_id = ctx.author.id
        timezone = await get_user_timezone(user_id)
        tz = pytz.timezone(timezone)

        now = datetime.now(tz)
        parsed_time = parser.parse(time_str, fuzzy=True, default=now)

        if parsed_time.tzinfo is None:
            parsed_time = tz.localize(parsed_time)

        if parsed_time <= now:
            if "tomorrow" in time_str.lower():
                parsed_time += timedelta(days=1)
            else:
                parsed_time += timedelta(days=1 if parsed_time.time() < now.time() else 0)

        repeat_str = repeat.lower() if repeat in ['daily', 'weekly'] else None
        alarm_id = await add_alarm(user_id, parsed_time.astimezone(pytz.utc), 
                                 message, ctx.channel.id, timezone, repeat_str)

        await ctx.send(
            f"(＞﹏＜ Alarm set for {parsed_time.strftime('%Y-%m-%d %H:%M')} ({timezone})\n"
            f"Message: {message}\n"
            f"ID: {alarm_id}"
            + (f"\nRepeat: {repeat_str}" if repeat_str else "")
        )
    except (ValueError, OverflowError):
        await ctx.send("~_~ Invalid time format. Try: '3pm', '15:30', or 'tomorrow 9am'")

@bot.command(name='listalarms')
async def list_alarms(ctx):
    user_id = ctx.author.id
    alarms = await get_user_alarms(user_id)

    if not alarms:
        await ctx.send("(￣o￣).zZ  No active alarms")
        return

    timezone = pytz.timezone(await get_user_timezone(user_id))
    alarm_list = []

    for alarm in alarms:
        local_time = datetime.fromisoformat(alarm['time']).astimezone(timezone)
        repeat_str = f" (Repeats {alarm['repeat']})" if alarm['repeat'] else ""
        alarm_list.append(
            f"** ID {alarm['id']}** - {local_time.strftime('%a %b %d %H:%M')}{repeat_str}\n"
            f" Message: {alarm['message']}"
        )

    embed = discord.Embed(
        title="Your Active Alarms",
        description="\n\n".join(alarm_list) or "No alarms set",
        color=discord.Color.gold()
    )
    await ctx.send(embed=embed)

@bot.command(name='deletealarm')
async def delete_alarm_command(ctx, alarm_id: int):
    user_alarms = await get_user_alarms(ctx.author.id)
    if any(alarm['id'] == alarm_id for alarm in user_alarms):
        await delete_alarm(alarm_id)
        await ctx.send(f"\\Alarm {alarm_id} deleted")
    else:
        await ctx.send("~_~ Alarm not found")

# Logging System
@bot.command(name='setlogchannel')
@commands.has_permissions(administrator=True)
async def set_log_channel_cmd(ctx, channel: discord.TextChannel):
    await set_log_channel(ctx.guild.id, channel.id)
    await ctx.send(f"📜 Logging channel set to {channel.mention}")

@bot.command(name='toggledeletelog')
@commands.has_permissions(administrator=True)
async def toggle_delete_log(ctx):
    new_state = await toggle_delete_logging(ctx.guild.id)
    if new_state is not None:
        status = 'enabled ▲' if new_state else 'disabled △'
        await ctx.send(f"◼ Message delete logging {status}")
    else:
        await ctx.send("~_~ Set a log channel first with !setlogchannel")

# Event Handlers
@bot.event
async def on_message_delete(message):
    if message.author.bot or not message.guild:
        return

    settings = await get_log_settings(message.guild.id)
    if settings and settings[1]:  # log_deletes is True
        channel = bot.get_channel(settings[0])
        if channel:
            content = message.content.replace('`', "'")[:900]
            await channel.send(
                f"🗑️ Message deleted in {message.channel.mention} by {message.author.mention}:\n"
                f"```{content}```"
            )

@bot.event
async def on_voice_state_update(member, before, after):
    if not member.guild:
        return

    settings = await get_log_settings(member.guild.id)
    if settings:
        channel = bot.get_channel(settings[0])
        if before.channel != after.channel:
            action = ""
            if not before.channel:
                action = f"joined 🔊 {after.channel.name}"
            elif not after.channel:
                action = f"left 🔇 {before.channel.name}"
            if channel and action:
                await channel.send(f"🎤 {member.mention} {action}")

# Alarm Checker
@tasks.loop(seconds=15)
async def check_alarms():
    due_alarms = await get_due_alarms()
    for alarm in due_alarms:
        try:
            channel = bot.get_channel(alarm['channel_id'])
            if channel:
                user = await bot.fetch_user(alarm['user_id'])
                await channel.send(f"🔔 {user.mention} **ALARM**: {alarm['message']}")

                # Handle recurring alarms
                if alarm['repeat']:
                    now = datetime.now(pytz.UTC)
                    next_time = datetime.fromisoformat(alarm['time'])
                    
                    # Reset base time to now to prevent drift
                    if alarm['repeat'] == 'daily':
                        next_time = now.replace(
                            hour=next_time.hour,
                            minute=next_time.minute,
                            second=0
                        ) + timedelta(days=1)
                    elif alarm['repeat'] == 'weekly':
                        next_time = now.replace(
                            hour=next_time.hour,
                            minute=next_time.minute,
                            second=0
                        ) + timedelta(weeks=1)
                    
                    try:
                        await update_alarm_time(alarm['id'], next_time)
                    except Exception as e:
                        print(f"Error updating recurring alarm {alarm['id']}: {e}")
                else:
                    await delete_alarm(alarm['id'])
        except Exception as e:
            print(f"Error triggering alarm: {e}")
            await delete_alarm(alarm['id'])


# Startup
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    await init_db()
    check_alarms.start()

try:
    bot.run(os.getenv('DISCORD_TOKEN'))
except discord.LoginFailure:
    print("~_~ Invalid token - check your DISCORD_TOKEN")
except Exception as e:
    print(f"~_~ Error starting bot: {e}")