#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests
import ssl
import socket
import whois
from urllib.parse import urlparse
import datetime
from bs4 import BeautifulSoup

from telegram.ext import Updater, MessageHandler, Filters

# ================================
# 🔧 CONFIG
# ================================
TELEGRAM_TOKEN = "8403701105:AAFdYXTHK9I0ChIJn7RxSb7ak1qN43GCkUs"
GOOGLE_API_KEY = "AIzaSyCOjfLfg3E2FXoEoaSd714iL91bpxZYN7g"
ADMIN_CHAT_ID = 1000022305  # Change to your Telegram ID


# ================================
# 1️⃣ GOOGLE SAFE BROWSING
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
# 2️⃣ DOMAIN AGE CHECK
# ================================
def check_domain_age(url):
    domain = urlparse(url).netloc

    try:
        info = whois.whois(domain)
        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        return (datetime.datetime.now() - creation_date).days
    except:
        return -1


# ================================
# 3️⃣ SSL CHECK
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
# 4️⃣ PHISHING WORD DETECTION
# ================================
def check_phishing_words(url):
    words = [
        "verify", "login", "reset", "wallet", "crypto",
        "bonus", "free", "bank", "update", "security",
        "unlock", "recover", "gift", "telegram-login"
    ]
    return any(w in url.lower() for w in words)


# ================================
# 5️⃣ SHORT URL EXPAND
# ================================
def expand_url(url):
    try:
        r = requests.get(url, timeout=6, allow_redirects=True)
        return r.url if r.url else url
    except:
        return url


# ================================
# 6️⃣ URL STRUCTURE CHECK
# ================================
def check_url_structure(url):
    if any(c in url for c in ["@", "%", "$", "!", "\\", "&"]):
        return True

    if len(url) > 120:
        return True

    return False


# ================================
# 7️⃣ RISK SCORE
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
# 8️⃣ FULL URL SCANNER
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
        "structure": check_url_structure(expanded),
    }

    results["risk"] = calculate_risk(results)
    return results


# ================================
# 9️⃣ FACEBOOK PAGE SCAM CHECK
# ================================
def check_facebook_page(url):
    result = {
        "valid": False,
        "followers": None,
        "has_transparency": False,
        "profile_pic": False,
        "posts_count": 0,
        "risk": 0
    }

    if "facebook.com" not in url:
        return result

    try:
        html = requests.get(url, timeout=8).text
    except:
        return result

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ").lower()
    result["valid"] = True

    # Followers
    match = re.search(r"([0-9,.]+)\s+followers", text)
    if match:
        followers = int(match.group(1).replace(",", ""))
        result["followers"] = followers

        if followers < 1000:
            result["risk"] += 30
        elif followers < 10000:
            result["risk"] += 10
    else:
        result["risk"] += 40

    # Transparency
    if "page transparency" in text:
        result["has_transparency"] = True
    else:
        result["risk"] += 25

    # Profile picture
    if "profilepicture" in html.lower():
        result["profile_pic"] = True
    else:
        result["risk"] += 20

    # Count posts
    posts = re.findall(r"ago·", text)
    result["posts_count"] = len(posts)

    if result["posts_count"] < 3:
        result["risk"] += 20

    # Scam keywords
    scam_words = ["giveaway", "win", "bonus", "gift", "free", "reward", "sponsored"]
    if any(w in text for w in scam_words):
        result["risk"] += 20

    return result


# ================================
# 🔥 TELEGRAM OUTPUT FORMAT
# ================================
def format_result(r):
    msg = "🔍 *PRO SCAN RESULTS*\n\n"
    msg += f"🔗 *Original:* {r['original']}\n"
    msg += f"↪ *Expanded:* {r['expanded']}\n\n"

    msg += f"🛡 *Google Blacklist:* {'❌ Unsafe' if r['safe_browsing'] else '✔ Clean'}\n"

    if r['domain_age'] == -1:
        msg += "📅 *Domain Age:* ❌ Unknown\n"
    else:
        msg += f"📅 *Domain Age:* {r['domain_age']} days\n"

    msg += f"🔒 *SSL:* {'✔ Valid' if r['ssl'] else '❌ No SSL'}\n"
    msg += f"🎯 *Phishing Words:* {'❌ Detected' if r['phishing_words'] else '✔ None'}\n"
    msg += f"🏗 *Structure:* {'❌ Suspicious' if r['structure'] else '✔ Normal'}\n"

    msg += f"\n⚠ *RISK SCORE:* {r['risk']}/100\n"

    if r['risk'] >= 70:
        msg += "\n🚨 *HIGH RISK — SCAM LINK!*"
    elif r['risk'] >= 40:
        msg += "\n⚠ *Medium Risk — Be careful.*"
    else:
        msg += "\n🟢 *Low Risk — Safe.*"

    return msg


# ================================
# 🚨 ADMIN ALERT
# ================================
def notify_admin(context, user, result):
    if result["risk"] >= 70:
        alert = f"""
🚨 *Suspicious Link Alert!*
👤 User: @{user}
🔗 {result['original']}
⚠ Risk Score: {result['risk']}/100
"""
        context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=alert, parse_mode="Markdown")


# ================================
# 🤖 TELEGRAM HANDLER (V13)
# ================================
def handle_message(update, context):

    url = update.message.text.strip()

    # Facebook Page Scan
    if "facebook.com" in url:
        fb = check_facebook_page(url)

        if fb["valid"]:
            fb_msg = "🔵 *FACEBOOK PAGE SCAN*\n\n"
            fb_msg += f"👥 Followers: {fb['followers']}\n"
            fb_msg += f"📝 Posts: {fb['posts_count']}\n"
            fb_msg += f"🔍 Transparency: {'✔ Yes' if fb['has_transparency'] else '❌ No'}\n"
            fb_msg += f"🖼 Profile Pic: {'✔ Yes' if fb['profile_pic'] else '❌ No'}\n"
            fb_msg += f"⚠ Risk Score: {fb['risk']}/100\n"

            if fb["risk"] >= 70:
                fb_msg += "\n🚨 *HIGH RISK Facebook Scam!*"
            elif fb["risk"] >= 40:
                fb_msg += "\n⚠ *Medium Risk — Be careful.*"
            else:
                fb_msg += "\n🟢 *Low Risk — Looks OK.*"

            update.message.reply_text(fb_msg, parse_mode="Markdown")
            return  # stop here (Facebook scan only)

    # Normal URL Scan
    if not url.startswith("http"):
        update.message.reply_text("❌ Please send a valid URL.")
        return

    update.message.reply_text("⏳ Scanning... please wait...")

    results = scan_url(url)
    reply = format_result(results)
    update.message.reply_text(reply, parse_mode="Markdown")

    notify_admin(context, update.message.from_user.username, results)


# ================================
# 🚀 RUN BOT
# ================================
def main():
    updater = Updater(TELEGRAM_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

    updater.start_polling()
    updater.idle()


main()
