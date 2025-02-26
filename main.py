#  --------------------------------------------------------------------------------------------
#                        !! CAUTION / READ FIRST !!
#  The code contains every offensive words & racial slurs possible
#  I am aware that False-positives are inevitable for something like this
#  Offensives & Slurs manually added instead of relying on AI or APIs
#  Feel free to fork this as this code is open-source
#  you can make changes in "NSFW_MAX_SCORE" , "ALLOWED_SOCIAL_LINKS", "ALLOWED_GIF_LINKS",  
#  "racialslurs", "offensive_names" & "WHITELIST_WORDS"!
#  Like add offensive & slurs from any language you want (Turkish, Russian, Japanese & etc)
#  Use it with care with improvements that you desire
#
#  This recipe also used by my Bot, BirchTree-Chan herself!
#  Feel free to invite the bot too! It has great features like the automod
#
#  Thank you for reading
#                         - </EmeraldDev06>
# ---------------------------------------------------------------------------------------------
import random
import nudenet
from nudenet import NudeDetector
classifier = NudeDetector()
import time
import datetime
import sqlite3
import re
import os
import aiohttp
import aiosqlite
import colorama
import asyncio
from colorama import Fore as F
from colorama import Style as S
from datetime import datetime,timedelta,timezone
from collections import defaultdict
import humanfriendly
from humanfriendly import parse_timespan
import discord
from discord.ext import commands, tasks
from discord import app_commands
from discord.app_commands import Choice

from dotenv import load_dotenv
load_dotenv()

mt_conn = sqlite3.connect('mute_roles.db')
mt_cursor = mt_conn.cursor()
    # Create a table to store mute roles
mt_cursor.execute('''CREATE TABLE IF NOT EXISTS mute_roles (
                       guild_id INTEGER PRIMARY KEY,
                       mute_role INTEGER
                     )''')
mt_conn.commit()


punishment_conn = sqlite3.connect('server_punishments.db')
punishment_cursor = punishment_conn.cursor()

punishment_cursor.execute('''
CREATE TABLE IF NOT EXISTS punishments (
    guild_id INTEGER,
    violation_type TEXT,        
    punishment_type TEXT,       
    timeout_duration TEXT,     
    PRIMARY KEY (guild_id, violation_type)
);
''')
punishment_cursor.execute('''
    CREATE TABLE IF NOT EXISTS active_punishments (
        guild_id INTEGER,
        member_id INTEGER,
        punishment_type TEXT,
        reason TEXT,
        start_time INTEGER,
        end_time INTEGER,
        PRIMARY KEY (guild_id, member_id, punishment_type)
    )
''')
punishment_cursor.execute('''
    CREATE TABLE IF NOT EXISTS link_policies (
        guild_id INTEGER,
        channel_id INTEGER,
        policy TEXT,  -- Choices: 'Gifs only', 'Socials only', 'Allow all links'
        PRIMARY KEY (guild_id, channel_id)
    )
''')
punishment_cursor.execute('''
    CREATE TABLE IF NOT EXISTS dm_settings (
    guild_id INTEGER NOT NULL,
    dm_enabled BOOLEAN NOT NULL DEFAULT 1,  -- 1 for enabled, 0 for disabled
    notify_for_violations BOOLEAN NOT NULL DEFAULT 1,  -- Send DMs for violations
    notify_for_warnings BOOLEAN NOT NULL DEFAULT 1,  -- Send DMs for warnings
    PRIMARY KEY (guild_id)
);
''')
punishment_cursor.execute('''
CREATE TABLE IF NOT EXISTS ignored_entities (
    server_id INTEGER,
    type TEXT,  -- 'member', 'role', or 'channel'
    entity_id INTEGER,
    punishment_type TEXT,
    UNIQUE(server_id, type, entity_id, punishment_type)
)
''')
punishment_conn.commit()

# -------------------------------------------------------------------------------------------------
# Bot Setup
# -------------------------------------------------------------------------------------------------

intents = discord.Intents.all()
intents.bans = True
intents.members = True
intents.guilds = True
token = os.environ['TOKEN']
bot = commands.Bot(command_prefix="!",intents=intents,help_command=None)

# --------------------------------------------------------------------------------------
# Asyncs & Variables
# --------------------------------------------------------------------------------------

NSFW_MAX_SCORE = 0.6
ALLOWED_SOCIAL_LINKS = re.compile(r"(discord\.gg|discord\.com|youtube\.com|twitter\.com|x\.com|instagram\.com|carrd\.co|threads\.net|reddit\.com|bsky\.app)", re.IGNORECASE)
ALLOWED_GIF_LINKS = re.compile(r"(tenor\.com|giphy\.com)", re.IGNORECASE)
colors = [0xe81416,0xffa500,0xfaeb36,0x79c314,0x487de7,0x4b369d,0x70369d]
racialslurs = ["卐", "卍", "retard", "nigger", "nigga","fag","faggot","chink","chinky","ching","chong"]
offensive_names = ["hoe","horny", "pussy", "ass", "fuck", "vagina", "shit", "cum","semen","ballslicker","bitch","cunt","bullshit","anal","blowjob","boner","boob","clit","cock","crotch","cunt","cybersex","dick","slut","easyslut","incest","pedo","pedophile","jackoff","jerkoff","condom","tits","titties","titty","rape","rapist","raping","raper","porn","futanari"]
WHITELIST_WORDS = {"assassin", "assassinate","assassinator", "cass", "cassie", "casserole","assume","bass","crass","grass","brass","titmouse","class","classes","pass","passed","assert","assessed","classic","assess","assessment","accumulate","analyst","uranus","basement","circumstance","advertisement","cucumber","cockpit","grape","watching","chinkapin","niger","spickard","nigeria","quantity","rap","rapper","sass","sassy","searching", "matching"}

class ModCMDS(app_commands.Group):
    ...
class AutomodSettingsCMDS(app_commands.Group):
    ...
class About(app_commands.Group):
    ...    
moderation = ModCMDS(name="moderation-commands",description="Moderation commands",default_permissions=discord.Permissions(1099511627776),allowed_installs=discord.app_commands.AppInstallationType(guild=True, user=False), allowed_contexts=discord.app_commands.AppCommandContext(guild=True, dm_channel=False, private_channel=False))
bot.tree.add_command(moderation)
automodstg = AutomodSettingsCMDS(name="automod-settings",description="Automod settings commands",default_permissions=discord.Permissions(8),allowed_installs=discord.app_commands.AppInstallationType(guild=True, user=False), allowed_contexts=discord.app_commands.AppCommandContext(guild=True, dm_channel=False, private_channel=False))
bot.tree.add_command(automodstg)
about = AutomodSettingsCMDS(name="about",description="About this bot",default_permissions=discord.Permissions(8),allowed_installs=discord.app_commands.AppInstallationType(guild=True, user=False), allowed_contexts=discord.app_commands.AppCommandContext(guild=True, dm_channel=False, private_channel=False))
bot.tree.add_command(about)        

async def get_mute_role(guild_id):
    async with aiosqlite.connect('mute_roles.db') as mt_conn:
        async with mt_conn.execute('SELECT mute_role FROM mute_roles WHERE guild_id = ?', (guild_id,)) as cursor:
            result = await cursor.fetchone()
            return result[0] if result else None

async def send_dm_to_member(member, message):
    try:
        embed = discord.Embed(title="Automod Notice",description=message,color=random.choice(colors))
        embed.set_author(name=bot.user.name,icon_url=bot.user.display_avatar.url)
        embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
        await member.send(embed=embed)
    except discord.Forbidden:
        pass
    except Exception as e:
        raise e

def get_punishment_for_violation(guild_id: int, violation_type: str):
    
    punishment_cursor.execute('''
    SELECT punishment_type, timeout_duration 
    FROM punishments 
    WHERE guild_id = ? AND LOWER(violation_type) = LOWER(?)
''', (guild_id, violation_type))

    punishment_data = punishment_cursor.fetchone()

    if punishment_data:
        return punishment_data
    else:
        return None

def is_allowed_link(message, policy):
    if policy == "Gifs only":
        return bool(ALLOWED_GIF_LINKS.search(message.content))
    elif policy == "Socials only":
        return bool(ALLOWED_SOCIAL_LINKS.search(message.content))
    elif policy == "Socials + Gifs only":
        return bool(ALLOWED_SOCIAL_LINKS.search(message.content) or ALLOWED_GIF_LINKS.search(message.content))
    elif policy == "Allow all links":
        return True
    return False

def has_embed_links_permission(member: discord.Member, channel: discord.TextChannel):
    permissions = channel.permissions_for(member)
    return permissions.embed_links          
        
def has_mod_permissions(member: discord.Member):
    return member.guild_permissions.manage_messages or member.guild_permissions.administrator        

async def apply_punishment(guild_id, member: discord.Member, punishment_type, reason, timeout_duration=None):
    if has_mod_permissions(member):
        return
        
    punishment_cursor.execute('''
        SELECT dm_enabled, notify_for_violations, notify_for_warnings 
        FROM dm_settings 
        WHERE guild_id = ?
    ''', (guild_id,))
    dm_settings = punishment_cursor.fetchone()

    if dm_settings:
        dm_enabled, notify_for_violations, notify_for_warnings = dm_settings

    current_time = int(time.time())
    end_time = None
    
    if timeout_duration:
        duration_seconds = parse_timespan(timeout_duration)
        end_time = current_time + duration_seconds 

    punishment_cursor.execute('''
        INSERT OR REPLACE INTO active_punishments (guild_id, member_id, punishment_type, reason, start_time, end_time)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (guild_id, member.id, punishment_type, reason, current_time, end_time))
    
    punishment_conn.commit()

    if dm_enabled:
        srvr = await bot.fetch_guild(guild_id)
        if punishment_type == "Mute" and notify_for_violations:   
            realreason = reason.replace(f"[{bot.user.name} Automod]", "")
            await send_dm_to_member(member, f"You got muted in **{srvr.name}**\n**Reasoning** - {realreason.strip()}")

        elif punishment_type == "Timeout" and notify_for_violations:
            realreason = reason.replace(f"[{bot.user.name} Automod]", "")   
            await send_dm_to_member(member, f"You got timeout in **{srvr.name}**\n**Reasoning** - {realreason.strip()}")    

        elif punishment_type == "Kick" and notify_for_violations:    
            realreason = reason.replace(f"[{bot.user.name} Automod]", "")     
            await send_dm_to_member(member, f"You have been kicked from **{srvr.name}**\n**Reasoning** - {realreason.strip()}")

        elif punishment_type == "Ban" and notify_for_violations:    
            realreason = reason.replace(f"[{bot.user.name} Automod]", "")     
            await send_dm_to_member(member, f"You have been banned from **{srvr.name}**\n**Reasoning** - {realreason.strip()}")            


    if punishment_type == 'Do Nothing':
        pass

    elif punishment_type == 'Mute':
        mute_role_id = await get_mute_role(guild_id) 
        if mute_role_id:
            mute_role = member.guild.get_role(mute_role_id)
            if mute_role:
                await member.add_roles(mute_role, reason=reason)
            else:
                pass
        else:
            pass
    
    elif punishment_type == 'Timeout':
        try:
            if timeout_duration:
                duration_seconds = parse_timespan(timeout_duration)
                unmute_time = discord.utils.utcnow() + timedelta(seconds=duration_seconds)
                await member.edit(timed_out_until=unmute_time,reason=reason)
        except Exception as e:
            raise e        

    elif punishment_type == 'Kick':
        await member.kick(reason=reason)

    elif punishment_type == 'Ban':
        await member.ban(reason=reason)

async def remove_punishment(guild_id, member_id):
    punishment_cursor.execute('''
        DELETE FROM active_punishments
        WHERE guild_id = ? AND member_id = ?
    ''', (guild_id, member_id))
    punishment_conn.commit()       

async def revoke_punishments_task():
    while True:
        current_time = int(time.time())
        punishment_cursor.execute('''
            SELECT guild_id, member_id, punishment_type 
            FROM active_punishments
            WHERE end_time IS NOT NULL AND end_time <= ?
        ''', (current_time,))
        
        punishments_to_revoke = punishment_cursor.fetchall()

        for guild_id, member_id, punishment_type in punishments_to_revoke:
            guild = bot.get_guild(guild_id)
            if not guild:
                continue 

            try:
                if punishment_type == 'Mute':
                    mute_role_id = await get_mute_role(guild_id)
                    if mute_role_id:
                        mute_role = guild.get_role(mute_role_id)
                        member = guild.get_member(member_id)
                        if member and mute_role and mute_role in member.roles:
                            await member.remove_roles(mute_role, reason=f"Punishment duration expired [{bot.user.name} Automod]")

                elif punishment_type == 'Ban':

                    user = await bot.fetch_user(member_id)

                    if user:
                        unban_guild = await bot.fetch_guild(guild_id)
                        await unban_guild.unban(user, reason=f"Punishment duration expired [{bot.user.name} Automod]")


                punishment_cursor.execute('''
                    DELETE FROM active_punishments
                    WHERE guild_id = ? AND member_id = ? AND punishment_type = ?
                ''', (guild_id, member_id, punishment_type))
                punishment_conn.commit()

            except Exception as e:
                print(f"Error in revoke_punishments_task: {e}")

        await asyncio.sleep(60)

def contains_blocked_words(message: str):
    blocked_pattern = r'|'.join(re.escape(word) for word in offensive_names) 
    blocked_regex = re.compile(blocked_pattern, re.IGNORECASE)

    for whitelist_word in WHITELIST_WORDS:
        whitelist_regex = re.compile(re.escape(whitelist_word), re.IGNORECASE)
        message = whitelist_regex.sub('', message)

    if blocked_regex.search(message):
        return True
    return False

def contains_slur_words(message: str):
    blocked_pattern = r'|'.join(re.escape(word) for word in racialslurs)
    blocked_regex = re.compile(blocked_pattern, re.IGNORECASE)

    for whitelist_word in WHITELIST_WORDS:
        whitelist_regex = re.compile(re.escape(whitelist_word), re.IGNORECASE)
        message = whitelist_regex.sub('', message)

    if blocked_regex.search(message):
        return True 
    return False

def get_allowed_link_types(policy):
    if policy == "Gifs only":
        return "GIF links (e.g., Tenor)"
    elif policy == "Socials Only":
        return "social media links (e.g., Discord, YouTube, Instagram, Twitter)"
    elif policy == "Socials + Gifs only":
        return "social media links (e.g., Discord, YouTube, Instagram, Twitter) & GIF links (e.g., Tenor)"
    elif policy == "Allow All Links":
        return "all types of links"
    else:
        return "no links"
        
async def cleanup_invalid_channels():
    await bot.wait_until_ready()
    while not bot.is_closed():
        punishment_cursor.execute('SELECT guild_id, channel_id FROM link_policies')
        policies = punishment_cursor.fetchall()

        for guild_id, channel_id in policies:
            guild = bot.get_guild(guild_id)
            if guild is None:
                punishment_cursor.execute('DELETE FROM link_policies WHERE guild_id = ?', (guild_id,))
            else:
                channel = guild.get_channel(channel_id)
                if channel is None:
                    punishment_cursor.execute('DELETE FROM link_policies WHERE guild_id = ? AND channel_id = ?', (guild_id, channel_id))

        punishment_conn.commit()
        print("Database cleanup completed. Waiting for the next cycle.")
        await asyncio.sleep(3600)

async def ensure_guild_in_db(guild_id: int):
    punishment_cursor.execute("SELECT guild_id FROM dm_settings WHERE guild_id = ?", (guild_id,))
    if punishment_cursor.fetchone() is None:
        punishment_cursor.execute(
            "INSERT INTO dm_settings (guild_id, dm_enabled, notify_for_violations, notify_for_warnings) VALUES (?, 0, 1, 1)",
            (guild_id,)
        )
        punishment_conn.commit()

# ------------------------------------------------------------------------------------------------------------
# On Ready events
# ------------------------------------------------------------------------------------------------------------        

@bot.event
async def on_ready():
    try:
        await bot.tree.sync()
    except Exception as e:
        raise e

@bot.listen('on_ready')
async def revokepunishment_ready():    
    try:
        bot.loop.create_task(revoke_punishments_task())
    except Exception as e:
        pass

@bot.listen('on_ready')
async def automod_ensure_ids_in_db():
    try:
        for guild in bot.guilds:
            await ensure_guild_in_db(guild.id)
    except Exception as e:
        raise e

@bot.listen('on_ready')
async def automod_dbclean_go():
    try:    
        bot.loop.create_task(cleanup_invalid_channels())
    except Exception as e:
        raise e                     

# ------------------------------------------------------------------------------------------------------------
# Auto Moderation Events!
# ------------------------------------------------------------------------------------------------------------    

@bot.listen('on_message')
async def links_bruh(message):
    if message.guild is None or message.author.bot:
        return
    if has_mod_permissions(message.author):
        return

    server_id = message.guild.id
    author_id = message.author.id
    channel_id = message.channel.id

   
    punishment_cursor.execute('''
    SELECT type, entity_id, punishment_type 
    FROM ignored_entities 
    WHERE server_id = ?
    ''', (server_id,))
    ignored_entities = punishment_cursor.fetchall()

    ignored_channels = {entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "channel"}
    ignored_members = {entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "member"}
    ignored_roles = {entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "role"}

    if channel_id in ignored_channels or author_id in ignored_members or any(role.id in ignored_roles for role in message.author.roles):
        return  

    link_pattern = re.compile(r'https?://[^\s]+')
    if link_pattern.search(message.content):
        punishment_cursor.execute('SELECT policy FROM link_policies WHERE guild_id = ? AND channel_id = ?', (server_id, channel_id))
        policy_data = punishment_cursor.fetchone()

        violation_type = "Links"
        message1 = None 

        if policy_data:
            policy = policy_data[0]

            if not is_allowed_link(message, policy):  
                allowed_links = get_allowed_link_types(policy)
                message1 = f"{message.author.mention}, only {allowed_links} are allowed in this channel."
            elif not has_embed_links_permission(message.author, message.channel):  
                message1 = f"{message.author.mention}, you do not have permission to send embedded links in this channel."
        else:
                message1 = f"{message.author.mention}, you do not have permission to send links in this channel."

        if message1:
            punishment_data = get_punishment_for_violation(server_id, violation_type)
            if punishment_data:
                punishment_type, timeout_duration = punishment_data
                reason = f"{violation_type} detected [{bot.user.name} Automod]"

                await message.delete()

                embed = discord.Embed(
                    title=f"{violation_type} Detected",
                    description=message1,
                    color=random.choice(colors)
                )
                embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
                embed.set_author(name=f"{bot.user.name}", icon_url=bot.user.display_avatar.url)
                
                await message.channel.send(embed=embed)
                await apply_punishment(server_id, message.author, punishment_type, reason, timeout_duration)
        
@bot.listen('on_message')
async def swears_slurs(message: discord.Message):
    if message.author.bot:
        return  
    if message.guild is None:
        return  
    if has_mod_permissions(message.author):
        return 

    server_id = message.guild.id
    author_id = message.author.id
    channel_id = message.channel.id
    guild_id = message.guild.id  
    violation_type = None

    
    punishment_cursor.execute('''
    SELECT type, entity_id, punishment_type 
    FROM ignored_entities 
    WHERE server_id = ?
    ''', (server_id,))
    ignored_entities = punishment_cursor.fetchall()

   
    ignored_channels = {
        (entity_id, punishment_type)
        for entity_type, entity_id, punishment_type in ignored_entities
        if entity_type == "channel"
    }
    ignored_members = {
        (entity_id, punishment_type)
        for entity_type, entity_id, punishment_type in ignored_entities
        if entity_type == "member"
    }
    ignored_roles = {
        (entity_id, punishment_type)
        for entity_type, entity_id, punishment_type in ignored_entities
        if entity_type == "role"
    }

    if contains_blocked_words(message.content):
        violation_type = "Inappropriate word(s)"
    elif contains_slur_words(message.content):
        violation_type = "Racial slur usage"

    if not violation_type:
        return

    if any(channel_id == entity_id and violation_type == punishment_type for entity_id, punishment_type in ignored_channels):
        return 

    if any(author_id == entity_id and violation_type == punishment_type for entity_id, punishment_type in ignored_members):
        return 

    ignored_roles_matched = [
        (role_id, punishment_type)
        for role_id, punishment_type in ignored_roles
        if role_id in {role.id for role in message.author.roles} and punishment_type == violation_type
    ]

    punishment_data = get_punishment_for_violation(guild_id, violation_type)
    if not punishment_data:
        return 

    punishment_type, timeout_duration = punishment_data
    reason = f"{violation_type} detected [{bot.user.name} Automod]"

    await message.delete()
    await apply_punishment(guild_id, message.author, punishment_type, reason, timeout_duration)

    embed = discord.Embed(
        title=f"{violation_type} Detected",
        description=f"{message.author.mention}, you are punished for **{violation_type}**.",
        color=random.choice(colors)
    )
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    embed.set_author(name=f"{bot.user.name}", icon_url=bot.user.display_avatar.url)
    await message.channel.send(f"{message.author.mention}", embed=embed)


spam_tracker = defaultdict(list) 
last_punishment_time = {} 

@bot.listen('on_message')
async def anti_spam(message: discord.Message):
    if message.guild is None or message.author.bot or has_mod_permissions(message.author):
        return
    
    server_id = message.guild.id
    author_id = message.author.id
    channel_id = message.channel.id


    punishment_cursor.execute('''
    SELECT type, entity_id, punishment_type 
    FROM ignored_entities 
    WHERE server_id = ?
    ''', (server_id,))
    ignored_entities = punishment_cursor.fetchall()


    ignored_channels = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "channel"
    }
    ignored_members = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "member"
    }
    ignored_roles = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "role"
    }


    if channel_id in ignored_channels:
        return 


    if author_id in ignored_members:
        return 

   
    author_roles = {role.id for role in message.author.roles}
    if any(role_id in ignored_roles for role_id in author_roles):
        return  

 
    member = message.author
    current_time = time.time()
    user_messages = spam_tracker[author_id]
    
    
    message_window = 8  
    spam_threshold = 8  
    punishment_cooldown = 7

    
    user_messages.append((message.content, current_time))
    spam_tracker[author_id] = [
        (msg, ts) for msg, ts in user_messages if current_time - ts < message_window
    ]

    
    if len(spam_tracker[author_id]) > spam_threshold: 
        last_punishment = last_punishment_time.get(author_id, 0)
        if current_time - last_punishment < punishment_cooldown:
            return
        
        punishment_data = get_punishment_for_violation(server_id, 'Member Safety')
        if not punishment_data:
            return
        
        punishment_type, timeout_duration = punishment_data
        reason = f"Spamming detected [{bot.user.name} Automod]"
        await apply_punishment(server_id, member, punishment_type, reason, timeout_duration)

        embed = discord.Embed(
            title="Spam Detected",
            description=f"{message.author.mention}, you are punished for spamming.",
            color=random.choice(colors)
        )
        embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
        embed.set_author(name=f"{bot.user.name}", icon_url=bot.user.display_avatar.url)
        await message.channel.send(f"{message.author.mention}", embed=embed)

        last_punishment_time[author_id] = current_time

        spam_tracker.pop(author_id, None)
            
raid_tracker = defaultdict(list)  

@bot.listen('on_message')
async def anti_raid(message):
    if message.guild is None:
        return
    if message.author.bot:
        return
    if has_mod_permissions(message.author):
        return
    
    server_id = message.guild.id
    author_id = message.author.id
    channel_id = message.channel.id

    punishment_cursor.execute('''
    SELECT type, entity_id, punishment_type 
    FROM ignored_entities 
    WHERE server_id = ?
    ''', (server_id,))
    ignored_entities = punishment_cursor.fetchall()

    ignored_channels = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "channel"
    }
    ignored_members = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "member"
    }
    ignored_roles = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "role"
    }

    if channel_id in ignored_channels:
        punishment_type = ignored_channels[channel_id]
        return 

 
    if author_id in ignored_members:
        punishment_type = ignored_members[author_id]
        return

   
    author_roles = {role.id for role in message.author.roles}
    ignored_roles_matched = author_roles & ignored_roles.keys()
    if ignored_roles_matched:
        for role_id in ignored_roles_matched:
            punishment_type = ignored_roles[role_id]
        return 

    guild_id = message.guild.id
    current_time = time.time()

   
    raid_tracker[guild_id].append((message.author.id, current_time))
    raid_tracker[guild_id] = [(user_id, ts) for user_id, ts in raid_tracker[guild_id] if current_time - ts < 10]  # Keep only last 10 seconds of messages
    
    if len(raid_tracker[guild_id]) > 20: 
        punishment_data = get_punishment_for_violation(guild_id, 'Member Safety')
        if not punishment_data:
            return
        punishment_type, timeout_duration = punishment_data
        reason = f"Raid detected [{bot.user.name} Automod]"
        await apply_punishment(guild_id, message.author, punishment_type, reason, timeout_duration)


ip_pattern = re.compile(
    r'\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.' 
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'
)

def is_probable_ip(ip: str) -> bool:
    """Additional validation to reduce false positives."""
    parts = list(map(int, ip.split('.')))
    
    
    if all(part < 10 for part in parts):
        return False
    
    return True 

@bot.listen('on_message')
async def anti_dox(message):
    if message.guild is None:
        return
    if message.author.bot:
        return

    guild_id = message.guild.id
    member = message.author

    server_id = message.guild.id
    author_id = message.author.id
    channel_id = message.channel.id

    punishment_cursor.execute('''
    SELECT type, entity_id, punishment_type 
    FROM ignored_entities 
    WHERE server_id = ?
    ''', (server_id,))
    ignored_entities = punishment_cursor.fetchall()


    ignored_channels = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "channel"
    }
    ignored_members = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "member"
    }
    ignored_roles = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "role"
    }

    
    if channel_id in ignored_channels:
        punishment_type = ignored_channels[channel_id]
        return  

    
    if author_id in ignored_members:
        punishment_type = ignored_members[author_id]
        return  

    
    author_roles = {role.id for role in message.author.roles}
    ignored_roles_matched = author_roles & ignored_roles.keys()
    if ignored_roles_matched:
        for role_id in ignored_roles_matched:
            punishment_type = ignored_roles[role_id]
        return  

    
    potential_ip = ip_pattern.search(message.content)
    if potential_ip:
        ip_address = potential_ip.group()
        if is_probable_ip(ip_address):  
            punishment_data = get_punishment_for_violation(guild_id, 'Member Safety')
            if not punishment_data:
                return
            punishment_type, timeout_duration = punishment_data
            reason = f"Doxxing (IP address) detected [{bot.user.name} Automod]"
            await message.delete()
            await apply_punishment(guild_id, member, punishment_type, reason, timeout_duration)
            embed = discord.Embed(title="Doxxing Detected",description=f"{message.author.mention}, you are punished for Doxxing (IP address) detected",color=random.choice(colors))
            embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
            embed.set_author(name=f"{bot.user.name}",icon_url=bot.user.display_avatar.url)
            await message.channel.send(f"{message.author.mention}",embed=embed)

# ------------------------------------------------------------------------------------------------------------
# NSFW Detector! (using nudenet library)
# ------------------------------------------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGE_DIR = os.path.join(BASE_DIR, 'images', 'for_nsfw_detection')
os.makedirs(IMAGE_DIR, exist_ok=True)

def ensure_directory_exists(directory_path):
    """Check if the directory exists and create it if it doesn't."""
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"Directory created: {directory_path}")
    else:
        pass

ensure_directory_exists(IMAGE_DIR)        

async def download_image(url, file_path):
    """Download an image from a URL and save it to the given file path."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status == 200:
                with open(file_path, "wb") as f:
                    f.write(await resp.read())
            else:
                return

async def check_nsfw(image_path):
    """Check if the image contains NSFW content using NudeNet."""
    try:
        # Validate the file existence
        if not os.path.exists(image_path):
            return None

        # Validate file type (optional, based on your use case)
        if not image_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.webp')):
            os.remove(image_path)
            return None

        # Run the classifier
        result = classifier.detect(image_path)
        if result is not None and len(result) > 0:
            return result  # Return the list of detections if valid
        else:
            os.remove(image_path)  # Clean up the file
            return None
    except AttributeError as attr_err:
        try:
            os.remove(image_path)  # Clean up the file
        except Exception as cleanup_err:
            print(f"Error cleaning up {image_path}: {cleanup_err}")
        return None
    except Exception as e:
        # Catch other exceptions and clean up
        print(f"Error during NSFW detection for {image_path}: {e}")
        try:
            os.remove(image_path)
        except Exception as cleanup_err:
            print(f"Error cleaning up {image_path}: {cleanup_err}")
        return None

async def handle_nsfw_avatar(user, guild=None):
    """Check if a user's avatar contains NSFW content."""
    if user.avatar:
        avatar_url = user.avatar.url
        file_name = f"{user.id}_avatar.jpg"
        file_path = os.path.join(IMAGE_DIR, file_name)
        ensure_directory_exists(IMAGE_DIR)
        
        # Download the avatar
        await download_image(avatar_url, file_path)
        
        # Check for NSFW content
        nsfw_result = await check_nsfw(file_path)

        if not nsfw_result:
            return

        # Process detection results
        for detection in nsfw_result:
            nsfw_class = detection['class']
            score = detection['score']

            # Set a threshold for NSFW content
            if nsfw_class in ['FEMALE_BREAST_EXPOSED', 'FEMALE_GENITALIA_EXPOSED', 'MALE_GENITALIA_EXPOSED', "ANUS_EXPOSED", "BUTTOCKS_EXPOSED"] and score > NSFW_MAX_SCORE:
                os.remove(file_path)
                await guild.ban(user, reason=f"NSFW profile picture detected [{bot.user.name} Anti NSFW Feature]")
        else:
            try:
                os.remove(file_path)
            except:
                pass
        cleanup_directory(IMAGE_DIR)        

@bot.listen('on_user_update')
async def nsfw_pfp_change_autoban(before, after):
    """Triggered when a user updates their profile. If it contains NSFW, it bans the member"""
    if before.avatar != after.avatar:
        for guild in bot.guilds:
            if after in guild.members:
                guild_id = guild.id
                await handle_nsfw_avatar(after, guild=guild)

@bot.listen('on_member_join')
async def nsfw_pfp_autoban(member):
    """Triggered when a new member joins a guild."""
    await handle_nsfw_avatar(member, guild=member.guild)

# Clean up image files in the directory
def cleanup_directory(directory_path):
    try:
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
    except Exception as e:
        print(f"Error cleaning up directory: {e}")

@bot.listen('on_message')
async def nsfw_detection_message(message):
    if message.guild is None or message.author == bot.user:
        return

    guild_id = message.guild.id 

    ensure_directory_exists(IMAGE_DIR)

    if isinstance(message.channel, discord.TextChannel) and not message.channel.nsfw:
        if message.attachments:
            for attachment in message.attachments:
                if any(attachment.filename.lower().endswith(ext) for ext in ['jpg', 'jpeg', 'png', 'gif']):
                    file_path = os.path.join(IMAGE_DIR, attachment.filename)
                    await attachment.save(file_path)

                    nsfw_result = await check_nsfw(file_path)
                    if not nsfw_result:
                        return
                    for detection in nsfw_result:
                        nsfw_class = detection['class']
                        score = detection['score']

                        if nsfw_class in ['FACE_MALE', 'FACE_FEMALE']:
                            if score > 0.9:
                                continue
                            else:
                                os.remove(file_path)
                                break

                        if nsfw_class in ['FEMALE_BREAST_EXPOSED', 'FEMALE_GENITALIA_EXPOSED',
                                          'MALE_GENITALIA_EXPOSED', 'ANUS_EXPOSED', 'BUTTOCKS_EXPOSED'] and score > NSFW_MAX_SCORE:
                            os.remove(file_path)
                            await handle_violation(message, guild_id, nsfw_class, score)
                            break
                        else:
                            os.remove(file_path)
                            break

    for word in message.content.split():
        if word.startswith(("http://", "https://")) and any(word.lower().endswith(ext) for ext in ['jpg', 'jpeg', 'png']):
            file_name = word.split("/")[-1]
            file_path = os.path.join(IMAGE_DIR, file_name)
            await download_image(word, file_path)

            nsfw_result = await check_nsfw(file_path)

            if not nsfw_result:
                return

            for detection in nsfw_result:
                nsfw_class = detection['class']
                score = detection['score']

                if nsfw_class in ['FACE_MALE', 'FACE_FEMALE']:
                    if score > 0.9:
                        continue
                    else:
                        try:
                            os.remove(file_path)
                        except:
                            pass
                        break

                if nsfw_class in ['FEMALE_BREAST_EXPOSED', 'FEMALE_GENITALIA_EXPOSED',
                                  'MALE_GENITALIA_EXPOSED', 'ANUS_EXPOSED', 'BUTTOCKS_EXPOSED'] and score > NSFW_MAX_SCORE:
                    try:
                        os.remove(file_path)
                    except:
                        pass
                    await handle_violation(message, guild_id, nsfw_class, score)
                    break
                else:
                    try:
                        os.remove(file_path)
                    except:
                        pass
                    break

    cleanup_directory(IMAGE_DIR)


async def handle_violation(message, guild_id, detection_source, score):
    """
    Handle detected NSFW violations.
    """
    author_id = message.author.id
    channel_id = message.channel.id
    violation_type = f"Inappropriate content detected by {detection_source} [{bot.user.name} Automod]"
    punishment_data = get_punishment_for_violation(guild_id, violation_type)

    if not punishment_data:
        await message.delete()
        embed = discord.Embed(
            title="Inappropriate Content Detected",
            description=(
                f"**{bot.user.name}** has detected inappropriate content posted outside of an age-restricted channel.\n\n"
                "This detection could be a false positive as the NSFW detector uses a trained model. "
                "We apologize for any inconvenience caused."
            ),
            color=random.choice(colors)
        )
        embed.set_author(name=f"{bot.user.name} [Anti-NSFW System]", icon_url=bot.user.display_avatar.url)
        embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
        await message.channel.send(embed=embed)
        return

    punishment_type, timeout_duration = punishment_data
    reason = f"{violation_type} detected [{bot.user.name} Automod]"
    server_id = message.guild.id
    author_id = message.author.id
    channel_id = message.channel.id

    punishment_cursor.execute('''
    SELECT type, entity_id, punishment_type 
    FROM ignored_entities 
    WHERE server_id = ?
    ''', (server_id,))
    ignored_entities = punishment_cursor.fetchall()

    ignored_channels = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "channel"
    }
    ignored_members = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "member"
    }
    ignored_roles = {
        entity_id: punishment_type for entity_type, entity_id, punishment_type in ignored_entities if entity_type == "role"
    }

    if channel_id in ignored_channels:
        punishment_type = ignored_channels[channel_id]
        await message.delete()  
        embed = discord.Embed(
            title="Inappropriate Content Detected",
            description=(
                f"**{bot.user.name}** has detected inappropriate content posted outside of an age-restricted channel.\n\n"
                "This detection could be a false positive as the NSFW detector uses a trained model. "
                "We apologize for any inconvenience caused."
            ),
            color=random.choice(colors)
        )
        embed.set_author(name=f"{bot.user.name} [Anti-NSFW System]", icon_url=bot.user.display_avatar.url)
        embed.set_footer(text="Be careful...")
        await message.channel.send(embed=embed)
        return

    if author_id in ignored_members:
        punishment_type = ignored_members[author_id]
        await message.delete()
        embed = discord.Embed(
            title="Inappropriate Content Detected",
            description=(
                f"**{bot.user.name}** has detected inappropriate content posted outside of an age-restricted channel.\n\n"
                "This detection could be a false positive as the NSFW detector uses a trained model. "
                "We apologize for any inconvenience caused."
            ),
            color=random.choice(colors)
        )
        embed.set_author(name=f"{bot.user.name} [Anti-NSFW System]", icon_url=bot.user.display_avatar.url)
        embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
        await message.channel.send(embed=embed)
        return

    author_roles = {role.id for role in message.author.roles}
    ignored_roles_matched = author_roles & ignored_roles.keys()
    if ignored_roles_matched:
      for role_id in ignored_roles_matched:
        punishment_type = ignored_roles[role_id]
        await message.delete()
        embed = discord.Embed(
            title="Inappropriate Content Detected",
            description=(
                f"**{bot.user.name}** has detected inappropriate content posted outside of an age-restricted channel.\n\n"
                "This detection could be a false positive as the NSFW detector uses a trained model. "
                "We apologize for any inconvenience caused."
            ),
            color=random.choice(colors)
        )
        embed.set_author(name=f"{bot.user.name} [Anti-NSFW System]", icon_url=bot.user.display_avatar.url)
        embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
        await message.channel.send(embed=embed)
      return

    await apply_punishment(guild_id, message.author, punishment_type, reason, timeout_duration)
    await message.delete()
    embed = discord.Embed(
        title="Inappropriate Content Detected & Punished",
        description=(
            f"**{bot.user.name}** has detected inappropriate content posted outside of an age-restricted channel.\n\n"
            "This detection could be a false positive as the NSFW detector uses a trained model. "
            "We apologize for any inconvenience caused."
        ),
        color=random.choice(colors)
    )
    embed.set_author(name=f"{bot.user.name} [Anti-NSFW System & Automod]", icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await message.channel.send(embed=embed)

# ------------------------------------------------------------------------------------------------------------
# Basic Moderation Commands!
# ------------------------------------------------------------------------------------------------------------

class ModMessage(discord.ui.Modal):
    def __init__(self, member: discord.Member, server_name: str, bot: commands.Bot, ctx: commands.Context):
        if member.global_name is not None:
            fullmem = member.global_name
        else:
            fullmem = member.name    
        super().__init__(title=f"Mod message for {fullmem}")
        self.member = member
        self.server_name = server_name
        self.bot = bot
        self.ctx = ctx

        self.topic = discord.ui.TextInput(
            label="Set a topic for the message", 
            style=discord.TextStyle.short, 
            required=True, 
            placeholder="Enter the topic", 
            max_length=256
        )

        self.message_content = discord.ui.TextInput(
            label="Now for the message", 
            style=discord.TextStyle.long, 
            required=True, 
            placeholder="Write the message here", 
            max_length=1024
        )

        self.add_item(self.topic)
        self.add_item(self.message_content)

    async def on_submit(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title="Notice From Moderator",
            description=(
                f"**Sent By** - <@{self.ctx.user.id}>\n"
                f"**Topic**\n{self.topic.value}\n"
                f"**Message**\n{self.message_content.value}"
            ),
            color=random.choice(colors)
        )
        embed.set_footer(text=f"Server - {self.server_name}")
        embed.set_author(name=f"{self.bot.user.name} [Mod Message]", icon_url=self.bot.user.display_avatar.url)

        try:
            # Send the message to the member
            await self.member.send(embed=embed)
            await interaction.response.send_message(f"Message sent to **{self.member.mention}**", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message(f"Failed to send message to **{self.member.mention}**", ephemeral=True)    
        except Exception as e:
            await interaction.response.send_message(f"Failed to send message to **{self.member.mention}**", ephemeral=True)
            raise e

def mod_role_check(ctx, member):
  return ctx.user.top_role > member.top_role


@moderation.command(name="moderation-message",description="Sends a moderation message to a member")
@app_commands.checks.has_permissions(moderate_members=True)
@app_commands.guild_only()
@app_commands.allowed_contexts(guilds=True, dms=False, private_channels=True)
async def modmessage(ctx: discord.Interaction,member: discord.Member):
    if member.id == ctx.user.id:
        await ctx.response.send_message("Sorry, you can't send an mod message to yourself.",ephemeral=True)
        return
    server_name = ctx.guild.name
    mod_modal = ModMessage(member=member, server_name=server_name, bot=bot, ctx=ctx)
    await ctx.response.send_modal(mod_modal)

@modmessage.error
async def on_app_command_error(inter: discord.Interaction, error):
    async def safe_send(content: str):
        if inter.response.is_done():
            await inter.followup.send(content, ephemeral=True)
        else:
            await inter.response.send_message(content, ephemeral=True)
    if discord.NotFound:
        await safe_send('Member not found...')      

@moderation.command(name="purge",description="Clears the messages in the channel")
@app_commands.describe(limit='Enter any number to purge amount of messages in a channel')
@app_commands.checks.has_permissions(manage_messages=True)
async def clean(ctx:discord.Interaction, limit: int):
    await ctx.response.send_message(f'Cleared {limit} messages',ephemeral=True)      
    await ctx.channel.purge(limit=limit)

@moderation.command(description="Creates a invite for your server",name="create-invite")
@app_commands.checks.has_permissions(administrator=True)
async def createinv(ctx: discord.Interaction): 
    try:
        invitelink = await ctx.channel.create_invite(max_uses=0, max_age=0)
        await ctx.response.send_message(f"Here's your invite: {invitelink}")
    except:
        await ctx.response.send_message(":x: You don't have the permission to Create invite")    

@bot.tree.context_menu(name="Send an mod message!")
@app_commands.checks.bot_has_permissions(moderate_members=True)
@app_commands.allowed_contexts(guilds=True, dms=False, private_channels=True)
async def modmessage_cm(ctx: discord.Interaction,member: discord.Member):
    if member.id == ctx.user.id:
        await ctx.response.send_message("Sorry, you can't send an mod message to yourself.",ephemeral=True)
        return
    server_name = ctx.guild.name
    mod_modal = ModMessage(member=member, server_name=server_name, bot=bot, ctx=ctx)
    await ctx.response.send_modal(mod_modal)

@modmessage_cm.error
async def on_app_command_error(inter: discord.Interaction, error):
    async def safe_send(content: str):
        if inter.response.is_done():
            await inter.followup.send(content, ephemeral=True)
        else:
            await inter.response.send_message(content, ephemeral=True)
    if discord.NotFound:
      await safe_send('Member not found...')    


@moderation.command(description="Kicks an member out of the server",name="kick-member")
@app_commands.checks.has_permissions(kick_members=True)
@app_commands.describe(member='Choose any member to kick')
@app_commands.describe(reason="Reasoning of the kick")
async def kick(ctx: discord.Interaction, member: discord.Member, *, reason:str = None):
    if not mod_role_check(ctx, member):
        await ctx.response.send_message("Failed to kick, lacking role hierarchy.",ephemeral=True)
        return
    if member.id == ctx.user.id:
        await ctx.response.send_message("Sorry, you can't kick yourself.",ephemeral=True)
        return
    
    await member.kick(reason=reason)
    kickembed = discord.Embed(title="Kick Successful!", description=f"""**Member** - {member.global_name}({member.display_name})\n**Member ID** - {member.id}\n**Reasoning** - {reason}\n**Responsible Moderator** - {ctx.user.global_name}({ctx.user})""", color=random.choice(colors))
    kickembed.set_author(name=bot.user.name, icon_url=bot.user.display_avatar.url)
    await ctx.response.send_message(embed=kickembed)

@kick.error
async def on_app_command_error(inter: discord.Interaction, error):
    async def safe_send(content: str):
        if inter.response.is_done():
            await inter.followup.send(content, ephemeral=True)
        else:
            await inter.response.send_message(content, ephemeral=True)
    if discord.NotFound:
      await safe_send('Member not found...')   

@moderation.command(name="ban-member", description="Bans an member out of the server")
@app_commands.describe(member='Choose any member to ban or use an Discord User ID to ban')
@app_commands.describe(reason='Reason for member ban')
@app_commands.checks.has_permissions(ban_members=True)
async def ban(ctx: discord.Interaction, member: discord.User, *, reason:str = None):
    if member.id == ctx.user.id:
        await ctx.response.send_message("Sorry, you can't ban yourself.",ephemeral=True)
        return
    if isinstance(member, discord.Member):
        if not mod_role_check(ctx, member):
            await ctx.response.send_message("Failed to ban, lacking role hierarchy.",ephemeral=True)
            return
        await ctx.response.defer()
        if not reason:
            mod_reason = f"Banned By {ctx.user}"
            reason = mod_reason 
        else:
            mod_reason = reason  
        await ctx.guild.ban(member,reason=reason)  
        if not member.global_name:  
            complete_mem = f"{member}"
        elif member.global_name == member:
            complete_mem = f"{member}"
        else:
            complete_mem = f"{member.global_name} ({member})"

        banembed = discord.Embed(title="Ban Successful!", description=f"""**Member** - {complete_mem}\n**Member ID** - {member.id}\n**Reasoning** - {mod_reason}\n**Responsible Moderator** - {ctx.user.global_name}({ctx.user})""", color=random.choice(colors))
        banembed.set_author(name=bot.user.name, icon_url=bot.user.display_avatar.url)
        await ctx.followup.send(embed=banembed)
    elif isinstance(member, discord.User):
        await ctx.response.defer()
        if not reason:
            mod_reason = f"Banned By {ctx.user}"
            reason = mod_reason 
        else:
            mod_reason = reason  
        await ctx.guild.ban(member,reason=reason)  
        if not member.global_name:  
            complete_mem = f"{member}"
        elif member.global_name == member:
            complete_mem = f"{member}"
        else:
            complete_mem = f"{member.global_name} ({member})"
            banembed = discord.Embed(title="Ban Successful!", description=f"""**Member** - {complete_mem}\n**Member ID** - {member.id}\n**Reasoning** - {mod_reason}\n**Responsible Moderator** - {ctx.user.global_name}({ctx.user})""", color=random.choice(colors))
            banembed.set_author(name=bot.user.name, icon_url=bot.user.display_avatar.url)
            await ctx.followup.send(embed=banembed)
 
@ban.error
async def on_app_command_error(inter: discord.Interaction, error):
   if isinstance (error ,discord.NotFound):
      await inter.response.send_message('Member not found...',ephemeral=True) 
    
@moderation.command(name="unban-member",description="Unbans an member from the server")
@app_commands.checks.has_permissions(ban_members=True)
async def unban(interaction: discord.Interaction, user_input: str):
    guild = interaction.guild
    if user_input.isdigit():
        user = await bot.fetch_user(int(user_input))
    else:
        user = None
        async for ban_entry in guild.bans():
            banned_user = ban_entry.user
            if user_input.lower() in banned_user.name.lower() or user_input.lower() in str(banned_user).lower():
                user = banned_user
                break

    if user:
        await interaction.response.defer()
        await guild.unban(user)
        unban_embed = discord.Embed(title="User Unbanned",description=f"**Affected User** - {user.mention}\n**User Global & Username** - {user.global_name} ({user.name})\n**User ID** - {user.id}\n**Responsible Moderator** - {interaction.user.mention}",color=random.choice(colors))
        unban_embed.set_author(name=bot.user.name, icon_url=bot.user.display_avatar.url)
        await interaction.followup.send(embed=unban_embed)
    else:
        await interaction.response.defer(ephemeral=True)
        await interaction.followup.send("User not found in the ban list.", ephemeral=True)


@unban.error
async def on_app_command_error(interaction: discord.Interaction, error):
    async def safe_send(content: str):
        if interaction.response.is_done():
            await interaction.followup.send(content, ephemeral=True)
        else:
            await interaction.response.send_message(content, ephemeral=True) 
    if discord.NotFound:
      await safe_send('Member not found or not banned.')
      return    


@moderation.command(name="mute-member",description="Mutes an member")
@app_commands.checks.has_permissions(moderate_members=True)
async def mute(ctx: discord.Interaction, member: discord.Member):
    if not mod_role_check(ctx, member):
       await ctx.response.send_message("Failed to mute, lacking role hierarchy.",ephemeral=True)
       return
    if member.id == ctx.user.id:
            await ctx.response.send_message("Sorry, you can't mute yourself .",ephemeral=True)
            return
    if member.id == ctx.guild.owner_id:
            await ctx.response.send_message("Server owners are unable to get punished because of the power",ephemeral=True)
            return 
    guild_id = ctx.guild.id
    mute_role_id = get_mute_role_id(guild_id)

    if mute_role_id:
        mute_role = ctx.guild.get_role(mute_role_id)

        if mute_role:
            await member.add_roles(mute_role)
            await ctx.response.send_message(f'{member.mention} has been muted.',ephemeral=True)
        else:
            await ctx.response.send_message('The mute role for this server does not exist. Please set it using `/role-settings setmute` command.',ephemeral=True)
    else:
        await ctx.response.send_message('No mute role set for this server. Please set it using `/role-settings setmute` command.',ephemeral=True)

def get_mute_role_id(guild_id):
    conn = sqlite3.connect('mute_roles.db')
    cursor = conn.cursor()

    cursor.execute('SELECT mute_role FROM mute_roles WHERE guild_id = ?', (guild_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0]
    else:
        return None

@moderation.command(name="unmute-member",description="Unmutes an member")
@app_commands.checks.has_permissions(moderate_members=True)
async def unmute(ctx: discord.Interaction, member: discord.Member):
    if not mod_role_check(ctx, member):
       await ctx.response.send_message("Failed to unmute, lacking role hierarchy.",ephemeral=True)
       return
    if member.id == ctx.user.id:
            await ctx.response.send_message("Sorry, you can't unmute yourself .",ephemeral=True)
            return
    if member.id == ctx.guild.owner_id:
            await ctx.response.send_message("Server owners are unable to get un-punished because of the power",ephemeral=True)
            return 
    guild_id = ctx.guild.id
    mute_role_id = get_mute_role_id(guild_id)

    if mute_role_id:
        mute_role = ctx.guild.get_role(mute_role_id)

        if mute_role:
            if mute_role in member.roles:
                await member.remove_roles(mute_role)
                await ctx.response.send_message(f'{member.mention} has been unmuted.',ephemeral=True)
            else:
                await ctx.response.send_message(f'{member.mention} is not muted.',ephemeral=True)
        else:
            await ctx.response.send_message('The mute role for this server does not exist. Please set it using `/role-settings setmute` command.',ephemeral=True)
    else:
        await ctx.response.send_message('No mute role set for this server. Please set it using `/role-settings setmute` command.',ephemeral=True)


@moderation.command(name="timeout",description="Mutes a member using timeout(If the Mute role doesn't work properly)")
@app_commands.checks.has_permissions(moderate_members=True)
async def timeout(ctx: discord.Interaction, member: discord.Member, time:str, *, reason:str = None):
    try:
        if not mod_role_check(ctx, member):
            await ctx.response.send_message("Failed to timeout, lacking role hierarchy.",ephemeral=True)
            return
        if member.id == ctx.user.id:
            await ctx.response.send_message("Sorry, you can't give yourself an timeout.",ephemeral=True)
            return
        if member.id == ctx.guild.owner_id:
            await ctx.response.send_message("Server owners are unable to get punished because of the power",ephemeral=True)
            return 

        time = humanfriendly.parse_timespan(time)
        
        max_time = 2419200
        if time > max_time:
            await ctx.response.send_message("Timeout duration cannot exceed 28 days.", ephemeral=True)
            return
        
        unmute_time = discord.utils.utcnow() + timedelta(seconds=time)

        await member.edit(timed_out_until=unmute_time,reason=reason)

        embed=discord.Embed(title="Timeout", description=f"**Member** - {member.global_name}(`{member.name}`)\n**Member ID** - {member.id}\n**Duration**- {humanfriendly.format_timespan(time)}\n**Reason** - `{reason}`", color=random.choice(colors))
        embed.set_author(name=bot.user.name, icon_url=bot.user.display_avatar.url)
        await ctx.response.send_message(embed=embed)
    except AttributeError as ae:
        await ctx.response.send_message("You have probably put bad arguments in `time` (it supports `s, m, h, d`, e.g., `5h`)", ephemeral=True)
    except Exception as e:
       raise e


@moderation.command(name="remove-timeout",description="Removes member's timeout")
@app_commands.checks.has_permissions(moderate_members=True)
async def revtimeout(ctx: discord.Interaction, member:discord.Member,*,reason:str = None):
    if not mod_role_check(ctx, member):
        await ctx.response.send_message("Failed to revoke timeout, lacking role hierarchy.",ephemeral=True)
        return
    if member.id == ctx.user.id:
        await ctx.response.send_message("Sorry, you can't revoke timeout from yourself",ephemeral=True)
        return
    if member.id == ctx.guild.owner_id:
        await ctx.response.send_message("You are an server owner, you can't revoke timeout from yourself.",ephemeral=True)
        return 
    await member.edit(timed_out_until=None,reason=reason)
    await ctx.response.send_message(f"{member.global_name}'s timeout has been revoked",ephemeral=True) 

@moderation.command(description="Locks a channel, prevent members from talking in there",name="lock-channel")
@app_commands.checks.has_permissions(manage_channels=True)
async def lock(ctx: discord.Interaction, channel : discord.TextChannel=None):
    await ctx.response.defer(ephemeral=True)
    await asyncio.sleep(1)
    channel = channel or ctx.channel
    overwrite = channel.overwrites_for(ctx.guild.default_role)
    overwrite.send_messages = False
    await channel.set_permissions(ctx.guild.default_role, overwrite=overwrite)
    await ctx.followup.send('Channel locked.', ephemeral=True)
  
@moderation.command(description='Unlocks a channel, unlocks messages for members', name="unlock-channel")
@app_commands.checks.has_permissions(manage_channels=True)
async def unlock(ctx: discord.Interaction, channel: discord.TextChannel = None):
    await ctx.response.defer(ephemeral=True)
    await asyncio.sleep(1)
    channel = channel or ctx.channel
    overwrite = channel.overwrites_for(ctx.guild.default_role)
    overwrite.send_messages = None
    await channel.set_permissions(ctx.guild.default_role, overwrite=overwrite)
    await ctx.followup.send('Channel unlocked.', ephemeral=True)

# You need to use commas when you adding members by either mentioning or using their User ID's
# Example "/test_cmds massban members: 123456789012345, 9876543210987654, 123456789012345 reason: testing purposes" (ID's wont work, it's there for an example)
@moderation.command(name="massban-members",description="Bans multiple members at once")
@app_commands.describe(members="Mention or list user IDs of the members to ban, separated by commas")
@app_commands.describe(reason="Reason for banning these members")
@app_commands.checks.has_permissions(administrator=True)
async def bulk_ban(ctx: discord.Interaction,members: str,reason: str):  # Defer to allow time for processing
    await ctx.response.defer(ephemeral=True)

    member_ids = members.replace(" ", "").split(",")

    banned_members = []
    failed_members = []

    for member_id in member_ids:
        try:
            await asyncio.sleep(1.6)
            user = await bot.fetch_user(int(member_id))

            member = ctx.guild.get_member(user.id)

            if member:
                if not mod_role_check(ctx, member):
                    failed_members.append((member_id, "You cannot ban a member with a higher or equal role."))
                    continue

            await ctx.guild.ban(user, reason=reason)
            banned_members.append(user)

        except Exception as e:
            failed_members.append((member_id, str(e)))

    if banned_members:
        banned_list = ", ".join([user.mention for user in banned_members])
        await ctx.followup.send(f"Successfully banned: {banned_list} for '{reason}'.", ephemeral=True)

    if failed_members:
        failed_list = ", ".join([f"<@{mid}> (Error: {err})" for mid, err in failed_members])
        await ctx.followup.send(f"Failed to ban the following members: {failed_list}", ephemeral=True)


@moderation.command(name="role-ban-members",description="Ban members with a specific role")
@app_commands.describe(role="Role to ban members with")
@app_commands.describe(reason="Reasoning for the ban")
@app_commands.checks.has_permissions(administrator=True)
async def ban_role(interaction: discord.Interaction,role: discord.Role,reason:str = None):
    guild = interaction.guild
    members_to_ban = [member for member in guild.members if role in member.roles]
    ban_success = 0
    ban_fail = 0

    if not members_to_ban:
        await interaction.response.send_message("No members with that role to ban.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    for member in members_to_ban:
        try:
            await member.ban(reason=f"{reason} [{bot.user.name} Role Ban]")
            ban_success += 1
        except Exception as e:
            ban_fail += 1
            await interaction.followup.send(f"Failed to ban {member.name}: {str(e)}", ephemeral=True)

    await interaction.followup.send(f"Banned **{ban_success}** Members with the role: {role.mention}. (Failed Bans? - **{ban_fail}** Members)",ephemeral=True)

@moderation.command(name="no-role-ban-members",description="Ban members without any roles")
@app_commands.describe(reason="Reasoning for no-role bans")
@app_commands.checks.has_permissions(administrator=True)
async def ban_no_role(interaction: discord.Interaction,reason:str = None):
    guild = interaction.guild
    members_to_ban = [member for member in guild.members if len(member.roles) == 1]
    await interaction.response.defer(ephemeral=True)
    if not members_to_ban:
        await interaction.followup.send("No members without roles to ban.", ephemeral=True)
        return

    for member in members_to_ban:
        try:
            await member.ban(reason=f"{reason} [{bot.user.name} No-Role Ban]")
            print(f"{member.global_name} ({member.name} / ID - {member.id}) Has been banned due to having no roles")
        except Exception as e:
            await interaction.followup.send(f"Failed to ban {member.name}: {str(e)}", ephemeral=True)

    await interaction.followup.send("Banned all members without roles.")   

# ------------------------------------------------------------------------------------------------------------
# Auto Moderation Setup Commands!
# ------------------------------------------------------------------------------------------------------------ 

@automodstg.command(name="setup-punishment",description="Set up custom punishments for Automod")
@app_commands.choices(violation_type=[
    Choice(name="Links", value="Links"),
    Choice(name="Racial slur usage", value="Racial slur usage"),
    Choice(name="Inappropriate word(s)", value="Inappropriate word(s)"),
    Choice(name="Member Safety", value="Member safety"),
    Choice(name="Inappropriate content", value="Inappropriate content")
])
@app_commands.choices(punishment_type=[
    Choice(name="Do Nothing", value="Do Nothing"),
    Choice(name="Mute", value="Mute"),
    Choice(name='Timeout', value="Timeout"),
    Choice(name="Kick", value="Kick"),
    Choice(name='Ban', value="Ban")
])
@app_commands.describe(violation_type="Type of violation")
@app_commands.describe(punishment_type="Punishment type (mute, kick, ban)")
@app_commands.describe(timeout_duration="Timeout duration (e.g., 10m, 1h) for temporary actions (optional)")
@app_commands.checks.has_permissions(administrator=True)
async def setup_punishment(
    interaction: discord.Interaction,
    violation_type: str,
    punishment_type: str,
    timeout_duration: str = None):
    automod_info = ""
    guild_id = interaction.guild_id

    # Validate punishment type and timeout
    if punishment_type in ["Kick", "Do Nothing"] and timeout_duration:
        await interaction.response.send_message(f"Silly, you can't set up timeout durations for {punishment_type}. Only temporary punishments like mutes can have durations.", ephemeral=True)
        return
    if punishment_type in ["Timeout", "Mute"] and not timeout_duration:
        await interaction.response.send_message(f"Silly, punishment duration is needed for temporary punishments", ephemeral=True)
        return

    punishment_cursor.execute('''
        INSERT OR REPLACE INTO punishments (guild_id, violation_type, punishment_type, timeout_duration)
        VALUES (?, ?, ?, ?)
    ''', (guild_id, violation_type, punishment_type, timeout_duration))
    punishment_conn.commit()
    embed = discord.Embed(title="Auto Moderation Setting Updated!",description=f"Punishment for `{violation_type}` added!\n**Punishment Type** - {punishment_type}\n{'**Timeout Duration** - ' + timeout_duration if timeout_duration else '**Timeout Duration** - Not Set!'}\n{automod_info}",color=random.choice(colors))        
    embed.set_author(name=f"{bot.user.name} [Automod System]",icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await interaction.response.send_message(embed=embed,ephemeral=True)

@automodstg.command(name="remove-punishment", description="Remove a specific punishment for a violation")
@app_commands.choices(violation_type=[
    Choice(name="Links", value="Links"),
    Choice(name="Racial slur usage", value="Racial slur usage"),
    Choice(name="Inappropriate word(s)", value="Inappropriate word(s)"),
    Choice(name="Member Safety", value="Member safety"),
    Choice(name="Inappropriate content", value="Inappropriate content")
])
@app_commands.checks.has_permissions(administrator=True)
async def remove_punishment(interaction: discord.Interaction,violation_type: str):

    guild_id = interaction.guild_id

    punishment_cursor.execute('''
        DELETE FROM punishments
        WHERE guild_id = ? AND violation_type = ?
    ''', (guild_id, violation_type))
    punishment_conn.commit()
    embed = discord.Embed(title="Auto Moderation Setting Updated!",description=f"Punishment for `{violation_type}` has been removed!",color=random.choice(colors))        
    embed.set_author(name=f"{bot.user.name} [Automod System]",icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await interaction.response.send_message(embed=embed,ephemeral=True)

@automodstg.command(name="clear-punishments", description="Delete all custom punishments for this server")
@app_commands.checks.has_permissions(administrator=True)
async def clear_punishments(interaction: discord.Interaction):

    guild_id = interaction.guild_id

    punishment_cursor.execute('''
        DELETE FROM punishments
        WHERE guild_id = ?
    ''', (guild_id,))
    punishment_conn.commit()

    embed = discord.Embed(title="Auto Moderation Setting Updated!",description=f"All custom punishments for this server have been cleared.",color=random.choice(colors))        
    embed.set_author(name=f"{bot.user.name} [Automod System]",icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await interaction.response.send_message(embed=embed,ephemeral=True)      

@automodstg.command(name="setup-linkpolicy",description="Set link policy for a specific channel")
@app_commands.choices(policy=[
    Choice(name="Gifs only", value="Gifs only"),
    Choice(name="Socials only", value="Socials only"),
    Choice(name="Socials + Gifs only", value="Socials + Gifs only"),
    Choice(name="Allow all links", value="Allow all links")
])
@app_commands.describe(channel="Choose an channel to change settings")
@app_commands.describe(policy="Type of link policy")
@app_commands.checks.has_permissions(administrator=True)
async def setup_link_policy(interaction: discord.Interaction,channel: discord.TextChannel,policy:str):
    guild_id = interaction.guild_id
    channel_id = channel.id

    punishment_cursor.execute('''
        INSERT OR REPLACE INTO link_policies (guild_id, channel_id, policy)
        VALUES (?, ?, ?)
    ''', (guild_id, channel_id, policy))
    punishment_conn.commit()

    embed = discord.Embed(title="Auto Moderation Setting Updated!",description=f"Link policy for {channel.mention} added!\n**Policy Type** - {policy}\n",color=random.choice(colors))        
    embed.set_author(name=f"{bot.user.name} [Automod System]",icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await interaction.response.send_message(embed=embed,ephemeral=True)

@automodstg.command(name="revoke-linkpolicy",description="Revoke link policy for a specific channel")
@app_commands.checks.has_permissions(administrator=True)
async def revoke_link_policy(interaction: discord.Interaction,channel: discord.TextChannel):
    guild_id = interaction.guild_id
    channel_id = channel.id

    punishment_cursor.execute('''
        DELETE FROM link_policies WHERE guild_id = ? AND channel_id = ?
    ''', (guild_id, channel_id))
    punishment_conn.commit()

    embed = discord.Embed(title="Auto Moderation Setting Updated!",description=f"Link policy for {channel.mention} has been revoked!",color=random.choice(colors))        
    embed.set_author(name=f"{bot.user.name} [Automod System]",icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await interaction.response.send_message(embed=embed,ephemeral=True)

@automodstg.command(name="setup-dms", description="Enable or disable automod DM notifications for the server")
@app_commands.choices(dm_enabled=[Choice(name='Enable', value="Enable"),Choice(name='Disable', value="Disable")])
@app_commands.choices(notify_for_violations=[Choice(name='Yes', value="Yes"),Choice(name='No', value="No")])
@app_commands.choices(notify_for_warnings=[Choice(name='Yes', value="Yes"),Choice(name='No', value="No")])
@app_commands.checks.has_permissions(administrator=True)
async def set_dm_settings(interaction: discord.Interaction, dm_enabled: str,notify_for_violations: str,notify_for_warnings: str):
    guild_id = interaction.guild_id
    dm_enabled_value = 1 if dm_enabled == "Enable" else 0
    notify_for_violations_value = 1 if notify_for_violations == "Yes" else 0
    notify_for_warnings_value = 1 if notify_for_warnings == "Yes" else 0

    punishment_cursor.execute('''
        INSERT OR REPLACE INTO dm_settings (guild_id, dm_enabled, notify_for_violations, notify_for_warnings)
        VALUES (?, ?, ?, ?)
    ''', (guild_id, dm_enabled_value, notify_for_violations_value, notify_for_warnings_value))
    punishment_conn.commit()

    embed = discord.Embed(title="Auto Moderation Setting Updated!",description=f"DM Settings updated! DMs are now {'**Enabled**' if dm_enabled_value else '**Disabled**'}\n**DMs for Violations** - {'Yes' if notify_for_violations_value else 'No'}\n**DMs for Warnings** - {'Yes' if notify_for_warnings_value else 'No'}.",color=random.choice(colors))        
    embed.set_author(name=f"{bot.user.name} [Automod System]",icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await interaction.response.send_message(embed=embed,ephemeral=True)

@automodstg.command(name="ignore-entity", description="Make Automod ignore members or roles (NSFW detector still removes content though)")
@app_commands.choices(punishment_type=[
    Choice(name="Links", value="Links"),
    Choice(name="Racial slur usage", value="Racial slur usage"),
    Choice(name="Inappropriate word(s)", value="Inappropriate word(s)"),
    Choice(name="Member Safety", value="Member safety"),
    Choice(name="Inappropriate content", value="Inappropriate content")
])
@app_commands.describe(punishment_type="Punishment type to choose.")
@app_commands.describe(member_or_role="Mention a member or role to ignore.")
async def ignore_entity(interaction: discord.Interaction, member_or_role: discord.Member | discord.Role, punishment_type: str):
    server_id = interaction.guild.id
    entity_id = member_or_role.id
    entity_type = "member" if isinstance(member_or_role, discord.Member) else "role"

    try:
        punishment_cursor.execute('''
        INSERT OR IGNORE INTO ignored_entities (server_id, type, entity_id, punishment_type)
        VALUES (?, ?, ?, ?)
        ''', (server_id, entity_type, entity_id, punishment_type))
        punishment_conn.commit()
        await interaction.response.send_message(f"{member_or_role.name} has been added to the ignore list with punishment type '{punishment_type}'.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Failed to add to ignore list: {e}", ephemeral=True)

# Add a command to ignore channels
@automodstg.command(name="ignore-channel", description="Ignore a channel for automod. (NSFW detector still removes content though)")
@app_commands.choices(punishment_type=[
    Choice(name="Links", value="Links"),
    Choice(name="Racial slur usage", value="Racial slur usage"),
    Choice(name="Inappropriate word(s)", value="Inappropriate word(s)"),
    Choice(name="Member Safety", value="Member safety"),
    Choice(name="Inappropriate content", value="Inappropriate content")
])
@app_commands.describe(punishment_type="Punishment type to choose.")
async def automod_ignore_channel(interaction: discord.Interaction, channel: discord.TextChannel,punishment_type: str):
    server_id = interaction.guild.id
    entity_id = channel.id
    entity_type = "channel"
    try:
        punishment_cursor.execute('''
        INSERT OR IGNORE INTO ignored_entities (server_id, type, entity_id, punishment_type)
        VALUES (?, ?, ?, ?)
        ''', (server_id, entity_type, entity_id, punishment_type))
        punishment_conn.commit()
        await interaction.response.send_message(f"{channel.name} has been added to the ignore list with punishment type '{punishment_type}'.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Failed to add to ignore list: {e}", ephemeral=True)

# Command to set the mute role for a guild
@automodstg.command(name="set-muterole",description="Sets up a mute role for your server")
@app_commands.checks.has_permissions(administrator=True)
async def set_mute_role(ctx: discord.Interaction, mute_role: discord.Role):
    guild_id = ctx.guild.id
    mute_role_id = mute_role.id

    mt_conn = sqlite3.connect('mute_roles.db')
    mt_cursor = mt_conn.cursor()

    mt_cursor.execute('INSERT OR REPLACE INTO mute_roles (guild_id, mute_role) VALUES (?, ?)', (guild_id, mute_role_id))
    mt_conn.commit()

    await ctx.response.send_message(f'Mute role set to {mute_role.mention} for this server.',ephemeral=True)        

# ------------------------------------------------------------------------------------------------------------
# About this bot.
# ------------------------------------------------------------------------------------------------------------

@about.command(name="bot",description="Good description for this bot")
async def abt_bot(interaction:discord.Interaction):
    bot_latency = bot.latency * 1000  # in milliseconds
    app_info = await bot.application_info()
    embed = discord.Embed(title="About this bot & code",description=f"This bot is created by **{app_info.owner.global_name}** ({app_info.owner.name})\nThis code & recipe made by **</EmeraldDev06>** It's Available at GitHub [Here](https://github.com/EmeraldBoyY2K6/discord.py-Advanced-Moderation-System)\n**Bot Latency** - `{bot_latency:.2f}ms`\n**Servers the bot is in** - `{len(bot.guilds)}`",color=random.choice(colors))
    embed.set_author(name=f"{bot.user.name}",icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await interaction.response.send_message(embed=embed)
    
@about.command(name="birch-tc",description="About the dev's main bot BirchTree-Chan!")
async def abt_bot(interaction:discord.Interaction):
    embed = discord.Embed(title="About BirchTree-Chan",description="**BirchTree-Chan** is a Discord Bot made by **</EmeraldDev06>**\nShe packs with important features\n- Name Based, Min. Account Age based, NSFW detecting Autobans (it has false-positives too but it's inevitable :c )\n- Logging System\n- Role Messages\n- Auto Moderation\n- Chatbot (It's not actually a chatbot as OpenAI's ChatGPT)\n- Blacklisting (Simplified Banned Member Information)\n- Welcome & Goodbye Messages\n - High-Risk Command Permissions\n- Miscellaneous Features\nAre you convinced? Then [invite the bot!](https://discord.com/oauth2/authorize?client_id=1045396531815137321)",color=random.choice(colors))    
    embed.set_author(name=f"{bot.user.name}",icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="Code by </EmeraldDev06> / On Discord & GitHub")
    await interaction.response.send_message(embed=embed)

@about.command(name="developer",description="Developer's information, Socials & Introduction")
async def devinfo(ctx: discord.Interaction):
    ind_dev = await bot.fetch_user(459409166298120214)
    embed=discord.Embed(title="Developer's Information", description=f"**His Discord**\n{ind_dev.global_name} ({ind_dev})\n\n**Discord Servers**\n[His Main server](https://discord.gg/VcGVchDKv5)\n[BirchTree-Chan's Server](https://discord.com/invite/J5AgJK4hAb)\n\n**His Socials**\n[Emerald's YouTube](https://www.youtube.com/@alloyedemerald2006)\n[Emerald's Instagram](https://www.instagram.com/alloyedemerald2006/)\n[Emerald's Twitter](https://twitter.com/EmeraldBoyY2K6)\n\n**Developer's Introduction**\nHi! My name is **AlloyedEmerald2006** you can also call me **EmeraldBoyY2K6**!\nMy occupation is Gachatuber And the developer of this code.\nI hope you like my code you found on GitHub, don't forget to follow my socials & GitHub if you want to!", color=random.choice(colors))
    embed.set_thumbnail(url=ind_dev.avatar.url)
    embed.set_author(name=bot.user.name, icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="meow uwu")
    await ctx.response.send_message(embed=embed)    

# ------------------------------------------------------------------------------------------------------------
# Bot Running!
# ------------------------------------------------------------------------------------------------------------ 

try:
    bot.run(token=token,reconnect=True)
except discord.LoginFailure as e:
    print(f"[{F.RED}ERROR - Login Failure!{S.RESET_ALL}] {e}")
except discord.RateLimited as e:
    print(f"[{F.RED}ERROR - Rate Limited!{S.RESET_ALL}] {e}")
except discord.HTTPException as e:
    print(f"[{F.RED}ERROR - Connection Failure!{S.RESET_ALL}] {e}")
except aiohttp.ClientConnectorCertificateError as e:        
    print(f"[{F.RED}ERROR - Unable to connect to discord!{S.RESET_ALL}] {e}\n(Discord is forbidden in Russia & Turkey. It's Recommended to use an VPN or Virtual Private Servers)")
except aiohttp.ClientConnectorError as e:
    print(f"[{F.RED}ERROR - Unable to connect to discord!{S.RESET_ALL}] {e}")
except ConnectionResetError as e:
    print(f"[{F.RED}ERROR - Unable to connect to discord!{S.RESET_ALL}] {e}")
except discord.ConnectionClosed as e:    
    print(f"[{F.RED}ERROR - Connection Closed!{S.RESET_ALL}] {e}")