import re
import requests
import ssl
import socket
import whois
import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from telegram.ext import Updater, MessageHandler, Filters


# ================================
# 🔧 CONFIG
# ================================
TELEGRAM_TOKEN = "8403701105:AAFdYXTHK9I0ChIJn7RxSb7ak1qN43GCkUs"
GOOGLE_API_KEY = "AIzaSyCOjfLfg3E2FXoEoaSd714iL91bpxZYN7g"
ADMIN_CHAT_ID = 1000022305   # Your Telegram User ID

MOBILE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10)",
}


# ================================
# 🔄 EXPAND URL (Better Version)
# ================================
def expand_url(url):
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        return r.url if r.url else url
    except:
        return url


# ================================
# 🔍 GOOGLE SAFE BROWSING
# ================================
def check_safe_browsing(url):
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        body = {
            "client": {"clientId": "scanner", "clientVersion": "1.0"},
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
        r = requests.post(endpoint, json=body)
        data = r.json()
        return "matches" in data
    except:
        return False


# ================================
# 📅 DOMAIN AGE
# ================================
def check_domain_age(url):
    try:
        domain = urlparse(url).netloc
        info = whois.whois(domain)
        created = info.creation_date

        if isinstance(created, list):
            created = created[0]

        age = (datetime.datetime.now() - created).days
        return age
    except:
        return -1


# ================================
# 🔐 SSL CHECK
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
    words = ["verify", "reset", "login", "crypto", "wallet", "bonus", "unlock"]
    return any(w in url.lower() for w in words)


# ================================
# ⚠ URL STRUCTURE
# ================================
def check_url_structure(url):
    bad_chars = ["@", "%", "$", "!", "\\"]
    return any(c in url for c in bad_chars)


# ================================
# 🧮 RISK SCORE
# ================================
def calculate_risk(r):
    score = 0
    if r["safe"]: score += 40
    if r["age"] != -1 and r["age"] < 60: score += 20
    if not r["ssl"]: score += 20
    if r["phish"]: score += 10
    if r["structure"]: score += 10
    return score


# ================================
# 🔍 MAIN URL SCAN
# ================================
def scan_url(url):
    expanded = expand_url(url)
    results = {
        "orig": url,
        "exp": expanded,
        "safe": check_safe_browsing(expanded),
        "age": check_domain_age(expanded),
        "ssl": check_ssl(expanded),
        "phish": check_phishing_words(expanded),
        "structure": check_url_structure(expanded),
    }
    results["risk"] = calculate_risk(results)
    return results


# ================================
# 📩 FORMAT URL RESULT
# ================================
def format_url(r):
    msg = "🔍 **PRO URL SCAN RESULTS** 🔍\n\n"
    msg += f"🔗 Original: {r['orig']}\n"
    msg += f"↪ Expanded: {r['exp']}\n\n"

    msg += f"🛡 Google Safe Browsing: {'❌ Unsafe' if r['safe'] else '✔ Clean'}\n"

    if r["age"] == -1:
        msg += "📅 Domain Age: ❓ Unknown\n"
    else:
        msg += f"📅 Domain Age: {r['age']} days\n"

    msg += f"🔒 SSL: {'✔ Yes' if r['ssl'] else '❌ No SSL'}\n"
    msg += f"🎯 Phishing Words: {'❌ Detected' if r['phish'] else '✔ None'}\n"
    msg += f"🌍 URL Structure: {'❌ Suspicious' if r['structure'] else '✔ Normal'}\n"
    msg += f"\n⚠ RISK SCORE: {r['risk']}/100\n"

    if r['risk'] >= 70:
        msg += "🚨 **HIGH RISK — Dangerous link!**"
    elif r['risk'] >= 40:
        msg += "⚠ Medium Risk — Be careful."
    else:
        msg += "🟢 Low Risk — Looks OK."

    return msg


# ==========================================
# 🔄 RESOLVE FACEBOOK SHARE LINKS
# ==========================================
def resolve_facebook_share(url):
    if "/share/" not in url:
        return url

    try:
        r = requests.get(url, headers=MOBILE_HEADERS, allow_redirects=True, timeout=10)
        return r.url
    except:
        return url


# ==========================================
# 🔍 FACEBOOK PAGE SCAN
# ==========================================
def check_facebook_page(url):
    try:
        r = requests.get(url, headers=MOBILE_HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, "lxml")

        # Followers
        followers = None
        tag = soup.find("div", string=re.compile("followers"))
        if tag:
            followers = tag.text.replace("followers", "").strip()

        # Posts
        posts = len(soup.find_all("article"))

        # Category
        cat = None
        cat_tag = soup.find("div", {"data-key": "tab_about"})
        if cat_tag:
            cat = cat_tag.text.strip()

        # Profile picture
        has_pic = bool(soup.find("image"))

        # Risk rules
        risk = 0
        if followers in [None, "0"]: risk += 30
        if posts == 0: risk += 30
        if not has_pic: risk += 15

        return {
            "url": url,
            "followers": followers,
            "posts": posts,
            "category": cat,
            "pic": has_pic,
            "risk": risk
        }

    except Exception:
        return None


# ================================
# 📩 FORMAT FACEBOOK RESULT
# ================================
def format_fb(f):
    if not f:
        return "❌ Cannot read Facebook page."

    msg = "🔵 **FACEBOOK PAGE SCAN**\n\n"
    msg += f"👥 Followers: {f['followers']}\n"
    msg += f"📝 Posts: {f['posts']}\n"
    msg += f"📂 Category: {f['category']}\n"
    msg += f"🖼 Profile Picture: {'✔ Yes' if f['pic'] else '❌ No'}\n"
    msg += f"⚠ Risk Score: {f['risk']}/100\n\n"

    if f["risk"] >= 70:
        msg += "🚨 **HIGH RISK Facebook Scam!**"
    elif f["risk"] >= 40:
        msg += "⚠ Medium Risk — Be careful."
    else:
        msg += "🟢 Low Risk — Looks OK."

    return msg


# ================================
# 🤖 HANDLE MESSAGES
# ================================
def handle_message(update, context):
    text = update.message.text.strip()

    # Facebook share → resolve
    if "facebook.com/share/" in text:
        update.message.reply_text("🔄 Resolving Facebook share link...")
        real = resolve_facebook_share(text)
        update.message.reply_text(f"↪ Real link: {real}")

        fb = check_facebook_page(real)
        update.message.reply_text(format_fb(fb), parse_mode="Markdown")
        return

    # Facebook page
    if "facebook.com" in text:
        fb = check_facebook_page(text)
        update.message.reply_text(format_fb(fb), parse_mode="Markdown")
        return

    # Normal URL
    if text.startswith("http"):
        update.message.reply_text("⏳ Scanning link...")
        r = scan_url(text)
        update.message.reply_text(format_url(r), parse_mode="Markdown")
        return

    update.message.reply_text("❌ Please send a valid link.")


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
