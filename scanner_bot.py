import re
import requests
import ssl
import socket
import whois
import datetime
from urllib.parse import urlparse
from telegram.ext import Updater, MessageHandler, Filters
from bs4 import BeautifulSoup

# ================================
# 🔧 CONFIG
# ================================
TELEGRAM_TOKEN = "8403701105:AAFdYXTHK9I0ChIJn7RxSb7ak1qN43GCkUs"
GOOGLE_API_KEY = "AIzaSyCOjfLfg3E2FXoEoaSd714iL91bpxZYN7g"
ADMIN_CHAT_ID = 1000022305  # Your Telegram ID


# ================================
# 🔍 GOOGLE SAFE BROWSING
# ================================
def check_safe_browsing(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    body = {
        "client": {"clientId": "pro-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(endpoint, json=body)
        return "matches" in r.json()
    except:
        return False


# ================================
# 📅 DOMAIN AGE
# ================================
def check_domain_age(url):
    domain = urlparse(url).netloc
    try:
        info = whois.whois(domain)
        created = info.creation_date

        if isinstance(created, list):
            created = created[0]

        if not created:
            return -1

        age_days = (datetime.datetime.now() - created).days
        return age_days

    except:
        return -1


# ================================
# 🔐 SSL CERTIFICATE
# ================================
def check_ssl(url):
    try:
        host = urlparse(url).netloc
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except:
        return False


# ================================
# 🧪 PHISHING WORD DETECTOR
# ================================
def check_phishing_words(url):
    words = [
        "verify", "login", "update", "reset", "free",
        "bonus", "claim", "wallet", "crypto", "telegram",
        "bank", "recover", "unlock"
    ]
    return any(w in url.lower() for w in words)


# ================================
# 🌍 SHORT LINK EXPANDER
# ================================
def expand_url(url):
    try:
        r = requests.get(url, timeout=7, allow_redirects=True)
        return r.url
    except:
        return url


# ================================
# ⚠ URL STRUCTURE CHECK
# ================================
def check_url_structure(url):
    bad = ["@", "$", "%", "!", "&", "\\"]
    if any(c in url for c in bad):
        return True
    if len(url) > 140:
        return True
    return False


# ================================
# 🧮 RISK SCORE
# ================================
def calc_risk(data):
    score = 0
    if data["safe"]: score += 40
    if data["age"] != -1 and data["age"] < 60: score += 20
    if not data["ssl"]: score += 20
    if data["phish"]: score += 15
    if data["struct"]: score += 5
    return score


# ================================
# 🔵 FACEBOOK PAGE SCANNER
# ================================
def scan_facebook(url):
    try:
        r = requests.get(url, timeout=8)
        soup = BeautifulSoup(r.text, "lxml")

        # Followers
        followers = None
        f_tag = soup.find(string=re.compile("followers"))
        if f_tag:
            followers = f_tag.replace("followers", "").strip()

        # Posts count
        posts = len(soup.find_all("div", {"role": "article"}))

        # Profile picture check
        profile_pic = bool(soup.find("img"))

        # Page category
        category = None
        c_tag = soup.find("div", string=re.compile("category", re.I))
        if c_tag:
            category = c_tag.strip()

        # Risk score for FB
        score = 0
        if not followers: score += 40
        if posts == 0: score += 30
        if not profile_pic: score += 20
        if not category: score += 10

        return {
            "followers": followers or "None",
            "posts": posts,
            "profile_pic": profile_pic,
            "category": category or "None",
            "risk": score,
        }

    except:
        return None


# ================================
# 🔍 MASTER URL SCANNER
# ================================
def scan_url(url):
    expanded = expand_url(url)

    data = {
        "original": url,
        "expanded": expanded,
        "safe": check_safe_browsing(expanded),
        "age": check_domain_age(expanded),
        "ssl": check_ssl(expanded),
        "phish": check_phishing_words(expanded),
        "struct": check_url_structure(expanded)
    }

    data["risk"] = calc_risk(data)
    return data


# ================================
# 📝 FORMAT MESSAGE — URL
# ================================
def format_url(data):
    msg = "🔍 **RESULTS — URL SCAN**\n\n"
    msg += f"🔗 Original: {data['original']}\n"
    msg += f"↪ Expanded: {data['expanded']}\n\n"

    msg += f"🛡 Google Blacklist: {'❌ Unsafe' if data['safe'] else '✔ Clean'}\n"

    if data['age'] == -1:
        msg += "📅 Domain Age: ❌ Unknown\n"
    else:
        msg += f"📅 Domain Age: {data['age']} days\n"

    msg += f"🔒 SSL: {'✔ Valid' if data['ssl'] else '❌ No SSL'}\n"
    msg += f"🎯 Phishing Words: {'❌ Found' if data['phish'] else '✔ None'}\n"
    msg += f"🌐 Structure: {'❌ Suspicious' if data['struct'] else '✔ Normal'}\n"
    msg += f"\n⚠ Risk Score: **{data['risk']}/100**\n"

    if data['risk'] >= 70:
        msg += "🚨 **HIGH RISK!**"
    elif data['risk'] >= 40:
        msg += "⚠ **Medium Risk**"
    else:
        msg += "🟢 **Low Risk**"

    return msg


# ================================
# 📝 FORMAT MESSAGE — FACEBOOK
# ================================
def format_fb(data):
    msg = "🔵 **FACEBOOK PAGE SCAN**\n\n"
    msg += f"👥 Followers: {data['followers']}\n"
    msg += f"📝 Posts: {data['posts']}\n"
    msg += f"📂 Category: {data['category']}\n"
    msg += f"🖼 Profile Picture: {'✔ Yes' if data['profile_pic'] else '❌ No'}\n"
    msg += f"⚠ Risk Score: **{data['risk']}/100**\n"

    if data['risk'] >= 70:
        msg += "🚨 **HIGH RISK Facebook Scam!**"
    elif data['risk'] >= 40:
        msg += "⚠ **Medium Risk!**"
    else:
        msg += "🟢 **Safe Page**"

    return msg


# ================================
# 🤖 MAIN MESSAGE HANDLER
# ================================
def handle(update, context):
    url = update.message.text.strip()

    if not url.startswith("http"):
        update.message.reply_text("❌ Please send a URL only.")
        return

    # FACEBOOK PAGE
    if "facebook.com" in url:
        update.message.reply_text("🔄 Scanning Facebook page...")
        fb = scan_facebook(expand_url(url))

        if fb:
            update.message.reply_text(format_fb(fb), parse_mode="Markdown")
        else:
            update.message.reply_text("❌ Unable to analyze this Facebook page.")
        return

    # NORMAL URL SCAN
    update.message.reply_text("⏳ Scanning...")
    data = scan_url(url)
    update.message.reply_text(format_url(data), parse_mode="Markdown")

    # Auto alert admin
    if data["risk"] >= 70:
        alert = f"🚨 ALERT\nUser: @{update.message.from_user.username}\nLink: {url}\nRisk: {data['risk']}"
        context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=alert)


# ================================
# 🚀 RUN BOT
# ================================
def main():
    updater = Updater(TELEGRAM_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(MessageHandler(Filters.text, handle))

    updater.start_polling()
    updater.idle()


main()
