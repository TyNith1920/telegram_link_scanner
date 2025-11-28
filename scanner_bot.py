import re
import requests
import ssl
import socket
import whois
from urllib.parse import urlparse
import datetime

from telegram.ext import Updater, MessageHandler, Filters

# -------------------------------
# 1. Google Safe Browsing Check
# -------------------------------
def check_safe_browsing(url):
    API_KEY = "AIzaSyCOjfLfg3E2FXoEoaSd714iL91bpxZYN7g"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    body = {
        "client": {"clientId": "link-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(endpoint, json=body)
        if response.status_code == 200 and "matches" in response.json():
            return True
    except:
        pass

    return False


# -------------------------------
# 2. Domain Age Check
# -------------------------------
def check_domain_age(url):
    domain = urlparse(url).netloc
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.datetime.now() - creation_date).days
        return age
    except:
        return -1


# -------------------------------
# 3. SSL Certificate Check
# -------------------------------
def check_ssl(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except:
        return False


# -------------------------------
# 4. Phishing Pattern Check
# -------------------------------
def check_phishing_patterns(url):
    patterns = [
        "verify","login","password","free","gift","bonus",
        "crypto","bank","telegram-login","support","update",
        "security","confirm","unlock","recover"
    ]
    for p in patterns:
        if p in url.lower():
            return True
    return False


# -------------------------------
# 5. URL Structure Check
# -------------------------------
def check_url_structure(url):
    parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        return True
    if any(c in url for c in ["@", "%", "$", "!", "\\"]):
        return True
    if len(url) > 120:
        return True
    return False


# -------------------------------
# FINAL SCAN
# -------------------------------
def scan_link(url):
    return {
        "safe_browsing": check_safe_browsing(url),
        "domain_age": check_domain_age(url),
        "ssl": check_ssl(url),
        "phishing": check_phishing_patterns(url),
        "structure": check_url_structure(url)
    }


# -------------------------------
# TELEGRAM HANDLER (PTB 13)
# -------------------------------
def handle_message(update, context):
    url = update.message.text.strip()

    if not url.startswith("http"):
        update.message.reply_text("❌ Please send a valid URL.")
        return

    update.message.reply_text("⏳ Scanning... please wait...")

    result = scan_link(url)

    reply = "🔍 SCAN RESULTS 🔍\n\n"
    reply += f"🛡 Google Blacklist: {'❌ Found' if result['safe_browsing'] else '✔ Clean'}\n"

    if result["domain_age"] == -1:
        reply += "📅 Domain Age: ❌ Unknown / Suspicious\n"
    elif result["domain_age"] < 60:
        reply += f"📅 Domain Age: ❌ {result['domain_age']} days (Too new)\n"
    else:
        reply += f"📅 Domain Age: ✔ {result['domain_age']} days\n"

    reply += f"🔒 SSL: {'✔ Valid' if result['ssl'] else '❌ No SSL'}\n"
    reply += f"🎯 Phishing Pattern: {'❌ Detected' if result['phishing'] else '✔ None'}\n"
    reply += f"🔗 URL Structure: {'❌ Suspicious' if result['structure'] else '✔ Normal'}\n"

    update.message.reply_text(reply)


# -------------------------------
# START BOT (Updater)
# -------------------------------
def main():
    TELEGRAM_TOKEN = "8403701105:AAFdYXTHK9I0ChIJn7RxSb7ak1qN43GCkUs"

    updater = Updater(TELEGRAM_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(MessageHandler(Filters.text, handle_message))

    updater.start_polling()
    updater.idle()


main()
