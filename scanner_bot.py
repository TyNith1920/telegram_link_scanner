import re
import requests
import ssl
import socket
import whois
from urllib.parse import urlparse
import datetime
import json

from telegram.ext import Updater, MessageHandler, Filters

# ================================
# 🔧 CONFIG
# ================================
TELEGRAM_TOKEN = "8403701105:AAFdYXTHK9I0ChIJn7RxSb7ak1qN43GCkUs"
GOOGLE_API_KEY = "AIzaSyCOjfLfg3E2FXoEoaSd714iL91bpxZYN7g"
ADMIN_CHAT_ID = 1000022305  # Change to your admin ID


# ================================
# 🔍 1. GOOGLE SAFE BROWSING
# ================================
def check_safe_browsing(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    body = {
        "client": {"clientId": "pro-scanner", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(endpoint, json=body)
        result = response.json()
        return "matches" in result
    except:
        return False


# ================================
# 📅 2. DOMAIN AGE CHECK
# ================================
def check_domain_age(url):
    domain = urlparse(url).netloc
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.datetime.now() - creation_date).days
        return age_days
    except:
        return -1  # Unknown / Suspicious


# ================================
# 🔐 3. SSL CHECK
# ================================
def check_ssl(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except:
        return False


# ================================
# 🎯 4. PHISHING WORDS
# ================================
def check_phishing_words(url):
    words = [
        "verify", "login", "reset", "wallet", "crypto",
        "bonus", "free", "bank", "update", "security",
        "unlock", "recover", "gift", "telegram-login"
    ]
    for w in words:
        if w in url.lower():
            return True
    return False


# ================================
# 🌍 5. SHORT URL EXPANDING
# ================================
def expand_url(url):
    try:
        r = requests.get(url, timeout=6, allow_redirects=True)
        return r.url if r.url else url
    except:
        return url


# ================================
# ⚠ 6. URL STRUCTURE CHECK
# ================================
def check_url_structure(url):
    suspicious_chars = ["@", "%", "$", "!", "\\", "&"]
    if any(c in url for c in suspicious_chars):
        return True
    if len(url) > 120:
        return True
    return False


# ================================
# 🧮 7. AUTO RISK SCORE
# ================================
def calculate_risk(data):
    score = 0

    if data["safe_browsing"]:
        score += 40
    if data["domain_age"] != -1 and data["domain_age"] < 60:
        score += 20
    if not data["ssl"]:
        score += 20
    if data["phishing_words"]:
        score += 15
    if data["structure"]:
        score += 5

    return score


# ================================
# 🔍 MAIN SCAN FUNCTION
# ================================
def scan_url(url):
    expanded = expand_url(url)

    results = {
        "original": url,
        "expanded": expanded,
        "safe_browsing": check_safe_browsing(expanded),
        "domain_age": check_domain_age(expanded),
        "ssl": check_ssl(expanded),
        "phishing_words": check_phishing_words(expanded),
        "structure": check_url_structure(expanded)
    }

    results["risk"] = calculate_risk(results)
    return results


# ================================
# 📩 FORMAT RESULT
# ================================
def format_result(r):
    msg = "🔍 **PRO SCAN RESULTS** 🔍\n\n"
    msg += f"🔗 **Original URL:** {r['original']}\n"
    msg += f"↪ **Expanded:** {r['expanded']}\n\n"

    msg += f"🛡 **Google Blacklist:** {'❌ Unsafe' if r['safe_browsing'] else '✔ Clean'}\n"

    if r['domain_age'] == -1:
        msg += "📅 **Domain Age:** ❌ Unknown / Suspicious\n"
    else:
        msg += f"📅 **Domain Age:** {r['domain_age']} days\n"

    msg += f"🔒 **SSL:** {'✔ Valid' if r['ssl'] else '❌ No SSL'}\n"
    msg += f"🎯 **Phishing Words:** {'❌ Detected' if r['phishing_words'] else '✔ None'}\n"
    msg += f"🌍 **Structure:** {'❌ Suspicious' if r['structure'] else '✔ Normal'}\n"
    msg += f"\n⚠ **RISK SCORE:** {r['risk']}/100\n"

    if r['risk'] >= 70:
        msg += "\n🚨 **HIGH RISK! Do NOT trust this link!**"
    elif r['risk'] >= 40:
        msg += "\n⚠ **Medium Risk — Be careful.**"
    else:
        msg += "\n🟢 **Low Risk — Looks OK.**"

    return msg


# ================================
# 🚨 AUTO-WARN ADMIN
# ================================
def notify_admin(context, user, result):
    if result["risk"] >= 70:
        alert = f"""
🚨 **Suspicious Link Alert!**

👤 User: {user}
🔗 Link: {result['original']}
⚠ Risk Score: {result['risk']}/100
"""
        context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=alert, parse_mode="Markdown")


# ================================
# 🤖 TELEGRAM HANDLER
# ================================
def handle_message(update, context):
    url = update.message.text.strip()

    if not url.startswith("http"):
        update.message.reply_text("❌ Please send a valid URL.")
        return

    update.message.reply_text("⏳ Scanning... please wait...")

    results = scan_url(url)
    reply = format_result(results)

    update.message.reply_text(reply, parse_mode="Markdown")

    # notify admin
    notify_admin(context, update.message.from_user.username, results)


# ================================
# 🚀 RUN BOT
# ================================
def main():
    updater = Updater(TELEGRAM_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(MessageHandler(Filters.text, handle_message))

    updater.start_polling()
    updater.idle()


main()
