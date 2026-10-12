"""Exercise extension loading and Discord command serialization without a login."""
import os
import subprocess
import sys


def test_all_extensions_load_and_close_offline(tmp_path):
    env = dict(os.environ, BOT_TESTING='1', SYNC_COMMANDS='false', AUTO_BACKUP='false', DATA_DIR=str(tmp_path))
    result = subprocess.run([sys.executable, '-c', '''
import asyncio
import main
async def smoke():
    async with main.bot:
        await main.bot.setup_hook()
        assert set(main.bot.cogs) == {'Guardian', 'Community', 'Privacy'}
        names = {cmd.name for cmd in main.bot.tree.get_commands()}
        assert {'alarm','report','case','dataexport','forgetme','health'} <= names
        for command in main.bot.tree.get_commands():
            command.to_dict(main.bot.tree)
    print('offline startup and shutdown passed')
asyncio.run(asyncio.wait_for(smoke(),20))
'''], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'offline startup and shutdown passed' in result.stdout
