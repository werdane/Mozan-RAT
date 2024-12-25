# MOZAN RAT (Remote Access Trojan) using Python and Discord Bots

<img src="https://github.com/user-attachments/assets/17ee8079-338c-4138-860d-940e6dea848a" alt="Description" width="800" height="400">

## Overview

This project is an educational Remote Access Trojan (RAT) written in Python. The RAT uses Discord bots to facilitate communication between the attacker and the victim. Commands that do not start with a `/` are treated as PowerShell commands. Commands starting with a `/` are interpreted as specific functionalities, such as file transfer, screenshots, logging, and more.

**Note:** This project is for educational purposes only. Unauthorized use of this software to access or control another person's device without their explicit permission is illegal and unethical.

## Features

- **Communication:** Utilizes Discord bots for communication between the attacker and the victim.
- **PowerShell Commands:** Any text that doesn't start with `/` is treated as a PowerShell command.
- **File Transfer:**
  - `/download` - Download files from the victim's device. 💻 ➡ 📁
  - `/upload` - Upload files to the victim's device. 📁 ➡ 💻
- **Screenshot:** `/screenshot` - Capture a screenshot of the victim's PC. 📸 💻
- **Network Information:** `/whatismyip` - Retrieve the victim's IP address. 😎 💻
- **Account Information:** `/getdiscord` - Retrieve the victim's Discord token. 🤣
- **Browser Data:** `/showhistory` - Retrieve the victim's browsing history. 😳
- **Keylogging:**
  - `/startlog` - Start the keystroke and click logger. ⌨ 🖱
  - `/retrievelog` - Retrieve the log. 📜
  - `/clearlog` - Clear the log. 📜 🚮
  - `/stoplog` - Stop the keylogger. ⌨ 🤚
- **Password Retrieval:** `/getpasswords` - Retrieve passwords from Edge and Chrome browsers. 🔐
- **Persistence:** Runs in the background and automatically starts on system startup.

DISCLAIMER: I CLAIM NO RESPONSIBILITY OVER HOW OTHERS USE THIS TOOL!

Pardon my poorly written code
