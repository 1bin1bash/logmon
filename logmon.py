import os
import re
import time
import logging
import asyncio
from telegram import Bot
import subprocess
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Thread
from typing import List, Dict, Set
import json
import urllib.parse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

TELEGRAM_BOT_TOKEN = "your_bot_token"
CHAT_ID = "your_chat_id"

with open("json/patterns.json", "r", encoding="utf-8") as json_file:
    json_data = json.load(json_file)

LOG_FILES = json_data["LOG_FILES"]
SUSPICIOUS_KEYWORDS = json_data["SUSPICIOUS_KEYWORDS"]
XSS_PATTERNS = json_data["XSS_PATTERNS"]
SQLI_PATTERNS = json_data["SQLI_PATTERNS"]

MAX_FAILED_ATTEMPTS: int = 5
REPORT_INTERVAL: int = 3600

FAILED_LOGIN_ATTEMPTS: Dict[str, int] = defaultdict(int)
BLOCKED_IPS: Set[str] = set()
FILE_SIZES: Dict[str, int] = {}
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

bot = Bot(token=TELEGRAM_BOT_TOKEN)

class LogFileHandler(FileSystemEventHandler):
    """Handles file system events for monitored log files."""

    def process_new_entries(self, log_file: str) -> None:
        """Process new entries in the log file."""
        try:
            with open(log_file, "r") as file:
                file.seek(FILE_SIZES.get(log_file, 0)) 
                lines = file.readlines()
                FILE_SIZES[log_file] = file.tell()  
                for line in lines:
                    self.analyze_log_entry(line, log_file)
        except Exception as e:
            logging.error(f"Error reading {log_file}: {e}")

    def analyze_log_entry(self, line: str, log_file: str) -> None:
        """Analyze a single log entry for suspicious activity."""
        decoded_line = urllib.parse.unquote(line)
        logging.info(f"Decoded Line: {decoded_line}")

        if any(c.islower() for c in decoded_line) and any(c.isupper() for c in decoded_line):
            logging.info(f"Decoded line contains mixed case characters: {decoded_line}")

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in decoded_line.lower():
                asyncio.run(self.send_alert(f"Suspicious Activity Detected in {log_file}:\n\n{decoded_line}"))

        for pattern in SQLI_PATTERNS:
            if re.search(pattern, decoded_line.lower()):
                asyncio.run(self.send_alert(f"SQL Injection Detected in {log_file}:\n\n{decoded_line}"))

        for pattern in XSS_PATTERNS:
            if re.search(pattern, decoded_line.lower()):
                asyncio.run(self.send_alert(f"XSS Attempt Detected in {log_file}:\n\n{decoded_line}"))

        if "failed password" in decoded_line.lower() or "invalid user" in decoded_line.lower():
            match = IP_PATTERN.search(decoded_line)
            if match:
                ip = match.group()
                FAILED_LOGIN_ATTEMPTS[ip] += 1
                if FAILED_LOGIN_ATTEMPTS[ip] >= MAX_FAILED_ATTEMPTS and ip not in BLOCKED_IPS:
                    self.block_ip(ip)

    async def send_alert(self, message: str) -> None:
        """Send an alert message via Telegram, splitting large messages if necessary."""
        try:
            max_length = 4096  
            for i in range(0, len(message), max_length):
                chunk = message[i:i + max_length]
                await bot.send_message(chat_id=CHAT_ID, text=chunk) 
                logging.info(f"Sent message chunk: {chunk[:50]}...") 
        except Exception as e:
            logging.error(f"Error sending Telegram message: {e}")

    def block_ip(self, ip: str) -> None:
        """Block an IP address using iptables."""
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            BLOCKED_IPS.add(ip)
            asyncio.run(self.send_alert(f"IP Blocked: {ip} after {MAX_FAILED_ATTEMPTS} failed login attempts!"))
        except Exception as e:
            asyncio.run(self.send_alert(f"Failed to block IP {ip}: {e}"))

    def on_modified(self, event) -> None:
        """Handle file modification events."""
        if event.src_path in LOG_FILES:
            self.process_new_entries(event.src_path)


async def monitor_file_size() -> None:
    """Monitor log file sizes for sudden increases."""
    global FILE_SIZES
    while True:
        for log_file in LOG_FILES:
            if os.path.exists(log_file):
                size = os.path.getsize(log_file)
                if log_file in FILE_SIZES:
                    old_size = FILE_SIZES[log_file]
                    if size > old_size * 1.5:
                        await bot.send_message(chat_id=CHAT_ID, text=f"Warning: {log_file} size increased suddenly!")
                FILE_SIZES[log_file] = size
        await asyncio.sleep(60)


async def send_periodic_report() -> None:
    """Send periodic security reports."""
    while True:
        await asyncio.sleep(REPORT_INTERVAL)
        report = "System Security Report:\n"
        report += f"Monitored Logs: {len(LOG_FILES)}\n"
        report += f"Blocked IPs: {len(BLOCKED_IPS)}\n"
        try:
            await bot.send_message(chat_id=CHAT_ID, text=report)
        except Exception as e:
            logging.error(f"Failed to send periodic report: {e}")


async def main() -> None:
    """Main function to start monitoring."""
    event_handler = LogFileHandler()
    observer = Observer()
    for log_file in LOG_FILES:
        if os.path.exists(log_file):
            observer.schedule(event_handler, path=os.path.dirname(log_file), recursive=False)
    observer.start()

    asyncio.create_task(monitor_file_size())
    asyncio.create_task(send_periodic_report())

    try:
        while True:
            await asyncio.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    asyncio.run(main())
