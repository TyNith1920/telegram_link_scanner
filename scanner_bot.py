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
# ⚙ CONFIG
# ================================
TELEGRAM_TOKEN = "8403701105:AAFdYXTHK9I0ChIJn7RxSb7ak1qN43GCkUs"
GOOGLE_API_KEY = "AIzaSyCOjfLfg3E2FXoEoaSd714iL91bpxZYN7g"
ADMIN_CHAT_ID = 1000022305  # Change to your Telegram ID


# ================================
# 🛡 CUSTOM HEADERS (ACT LIKE REAL PHONE)
# ================================
MOBILE_HEADERS = {
    "User-Agent":
        "Mozilla/5.0 (Linux; Android 10; SM-G975F) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Mobile Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9"
}


# ================================
# 🔍 GOOGLE SAFE BROWSING
# ================================
def check_safe_browsing(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    body = {
        "client": {"clientId": "pro-scanner", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(endpoint, json=body).json()
        return "matches" in response
    except:
        return False


# ================================
# 📅 DOMAIN AGE
# ================================
def check_domain_age(url):
    domain = urlparse(url).netloc
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        return (datetime.datetime.now() - creation).days
    except:
        return -1


# ================================
# 🔒 SSL Check
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
# 🎯 PHISHING WORDS
# ================================
def check_phishing_words(url):
    words = ["verify", "login", "reset", "wallet", "crypto",
             "bonus", "free", "bank", "update", "security",
             "unlock", "recover", "gift"]
    return any(w.lower() in url.lower() for w in words)


# ================================
# 🔁 EXPAND SHORT URL
# ================================
def expand_url(url):
    try:
        r = requests.get(url, timeout=6, allow_redirects=True)
        return r.url
    except:
        return url


# ================================
# 🧩 STRUCTURE CHECK
# ================================
def check_url_structure(url):
    bad_chars = ["@", "%", "$", "&", "!", "\\"]
    if any(ch in url for ch in bad_chars):
        return True
    if len(url) > 120:
        return True
    return False


# ================================
# ⚠ RISK SCORE ENGINE
# ================================
def calculate_risk(data):
    score = 0
    if data["safe"]: score += 40
    if data["age"] != -1 and data["age"] < 60: score += 20
    if not data["ssl"]: score += 20
    if data["phish"]: score += 15
    if data["struct"]: score += 5
    return score


# ================================
# 🔍 URL SCAN
# ================================
def scan_url(url):
    expanded = expand_url(url)

    result = {
        "orig": url,
        "exp": expanded,
        "safe": check_safe_browsing(expanded),
        "age": check_domain_age(expanded),
        "ssl": check_ssl(expanded),
        "phish": check_phishing_words(expanded),
        "struct": check_url_structure(expanded)
    }

    result["risk"] = calculate_risk(result)
    return result


# ================================
# 🔵 IMPROVED FACEBOOK PAGE SCANNER
# ================================
def check_facebook_page(url):
    fb = {
        "valid": False,
        "followers": None,
        "likes": None,
        "category": None,
        "posts": 0,
        "profile_pic": False,
        "risk": 0
    }

    if "facebook.com" not in url:
        return fb

    # Use mobile version for scraping
    mobile_url = url.replace("www.facebook.com", "m.facebook.com")

    try:
        html = requests.get(mobile_url, headers=MOBILE_HEADERS, timeout=10).text
    except:
        return fb

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ").lower()
    fb["valid"] = True

    # Followers
    match = re.search(r"([0-9,.]+)\s+followers", text)
    if match:
        fb["followers"] = int(match.group(1).replace(",", ""))
        if fb["followers"] < 500: fb["risk"] += 40
        elif fb["followers"] < 2000: fb["risk"] += 20

    else:
        fb["risk"] += 30  # no follower info

    # Category
    cat = soup.find("div", string=re.compile("category", re.I))
    if cat:
        fb["category"] = cat.text.strip()

    # Posts detection
    posts = re.findall(r"ago", text)
    fb["posts"] = len(posts)
    if fb["posts"] <= 1:
        fb["risk"] += 25

    # Profile picture
    if "profile picture" in text or "profilephoto" in html.lower():
        fb["profile_pic"] = True
    else:
        fb["risk"] += 20

    # Scam terms
    scam_words = ["win", "bonus", "gift", "reward", "giveaway", "free", "លុយឥតគិត"]
    if any(w in text for w in scam_words):
        fb["risk"] += 30

    return fb


# ================================
# 📩 FORMAT FACEBOOK RESULT
# ================================
def format_fb(fb):
    msg = "🔵 *FACEBOOK PAGE SCAN*\n\n"

    msg += f"👥 Followers: {fb['followers']}\n"
    msg += f"📝 Posts: {fb['posts']}\n"
    msg += f"🏷 Category: {fb['category']}\n"
    msg += f"🖼 Profile Pic: {'✔ Yes' if fb['profile_pic'] else '❌ No'}\n"
    msg += f"⚠ Risk Score: {fb['risk']}/100\n\n"

    if fb["risk"] >= 70:
        msg += "🚨 *HIGH RISK Facebook Scam!*"
    elif fb["risk"] >= 40:
        msg += "⚠ *Medium Risk Page — Be careful.*"
    else:
        msg += "🟢 *Low Risk — Looks OK.*"

    return msg


# ================================
# 📩 FORMAT URL RESULT
# ================================
def format_url(r):
    msg = "🔍 *PRO URL SCAN RESULTS*\n\n"
    msg += f"🔗 *Original:* {r['orig']}\n"
    msg += f"↪ *Expanded:* {r['exp']}\n\n"

    msg += f"🛡 Google Blacklist: {'❌ Unsafe' if r['safe'] else '✔ Clean'}\n"
    msg += f"📅 Domain Age: {r['age']} days\n" if r['age'] != -1 else "📅 Domain Age: ❌ Unknown\n"
    msg += f"🔒 SSL: {'✔ Valid' if r['ssl'] else '❌ No SSL'}\n"
    msg += f"🎯 Phishing Words: {'❌ Found' if r['phish'] else '✔ None'}\n"
    msg += f"🏗 Structure: {'❌ Suspicious' if r['struct'] else '✔ Normal'}\n"
    msg += f"\n⚠ Risk Score: {r['risk']}/100\n"

    if r["risk"] >= 70:
        msg += "\n🚨 *HIGH RISK — SCAM LINK!*"
    elif r["risk"] >= 40:
        msg += "\n⚠ Medium Risk"
    else:
        msg += "\n🟢 Low Risk"

    return msg


# ================================
# 🤖 TELEGRAM HANDLER
# ================================
def handle_message(update, context):
    text = update.message.text.strip()

    # Facebook page scan
    if "facebook.com" in text:
        fb = check_facebook_page(text)
        reply = format_fb(fb)
        update.message.reply_text(reply, parse_mode="Markdown")
        return

    # Normal URL scan
    if not text.startswith("http"):
        update.message.reply_text("❌ Please send a valid URL.")
        return

    update.message.reply_text("⏳ Scanning... please wait...")
    r = scan_url(text)
    update.message.reply_text(format_url(r), parse_mode="Markdown")


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
