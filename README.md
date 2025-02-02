# Log Monitoring and Alerting Tool  

This Python-based log monitoring tool scans system log files for suspicious activities, including multiple failed login attempts, potential security breaches, and specific patterns like SQL Injection, XSS attacks, and more. It sends alerts via Telegram when such activities are detected.

## Features
- Monitor multiple log files (e.g., `/var/log/`, etc.)
- Detect suspicious activities such as failed login attempts, unauthorized access, SQL Injection, XSS attempts, etc.
- Alert the user via Telegram Bot when suspicious patterns are detected
- Periodic reports summarizing blocked IPs and monitored logs
- Block IP addresses that exceed the configured number of failed login attempts
- Support for dynamic log file monitoring with `watchdog`
- Detect significant file size increases to spot abnormal log activity

## Requirements

Before running the tool, ensure the following dependencies are installed:

1. **Python 3.7+**
2. **Required Python packages**:
   - `python-telegram-bot`
   - `watchdog`
   - `requests`
   - `subprocess`

You can install them via pip:

```bash
pip install -r requirements.txt
```
1. Telegram Bot Setup:
You need to set up a Telegram bot to receive alerts:

Create a bot using BotFather on Telegram and get your bot's API token.
Add your CHAT_ID by contacting your bot and using this tool to get your chat ID.
2. Log Files Configuration:
Specify the log files you want to monitor. By default, the script checks:

/var/log/auth.log
/var/log/syslog
/var/log/nginx/access.log
You can modify the LOG_FILES list in the script to include additional log files.

3. Suspicious Keywords:
The tool looks for specific keywords in the logs (e.g., "failed", "unauthorized", "SQL Injection", etc.). Modify the SUSPICIOUS_KEYWORDS list to add or remove keywords based on your needs.

4. IP Blocking Threshold:
The tool will block an IP address after a certain number of failed login attempts (MAX_FAILED_ATTEMPTS). Modify this value to suit your system's security requirements.

Usage
Clone or download the repository.
Configure your Telegram bot and log files as explained above.
Run the script using Python:
bash
Copy
Edit
python3 logmon.py
The script will continuously monitor the log files for suspicious activities and alert you via Telegram. You can stop the script using Ctrl+C.

Troubleshooting
Error: ImportError: cannot import name 'Bot' from 'telegram'
Ensure that you have the correct version of the python-telegram-bot library. If you're using version 20+, the usage syntax has changed. You may need to adjust the import statements:

python
Copy
Edit
from telegram import Bot
Issue: No alerts received on Telegram
Ensure your TELEGRAM_BOT_TOKEN and CHAT_ID are correctly set.
Make sure the bot has permission to message your Telegram account.
Check your internet connection or firewall settings.
License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
Telegram API for sending alerts
watchdog library for monitoring file changes
The open-source community for contributing to security tools



## Running as a Systemd Service

To run the log monitoring tool as a background service using `systemd`, follow these steps:

### 1. Create a Systemd Service File

Create a new systemd service file for the script:

```bash
sudo nano /etc/systemd/system/logmon.service
```

```
[Unit]
Description=Log Monitoring Tool
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path_to/logmon.py
WorkingDirectory=/path_to_WorkingDirectory like WorkingDirectory=/opt/logmon

Restart=always
User=root
StandardOutput=append:/var/log/logmon.log
StandardError=append:/var/log/logmon.log

[Install]
WantedBy=multi-user.target
```





### Reload systemd to recognize the new service
```sudo systemctl daemon-reload```

### Enable the service to start on boot
```sudo systemctl enable logmon.service```

### Start the service immediately
```sudo systemctl start logmon.service```





# Created By /bin/basha
## Telegram:  https://t.me/bin1basha

