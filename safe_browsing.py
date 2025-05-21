import requests
import csv
import socket

API_KEY = ''

def is_url_safe(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # ❗ Domain existence check
    if not domain_exists(url):
        return False

    try:
        if not check_google_safe_browsing(url):
            return False
    except Exception as e:
        print("Google Safe Browsing failed:", e)
        return False

    try:
        if not check_phishtank_csv(url):
            return False
    except Exception as e:
        print("Phishtank fallback failed:", e)
        return True

    return True


def check_google_safe_browsing(url):
    print(f"\n🔍 Checking Google Safe Browsing for: {url}")
    if API_KEY == "":
        print("❌ API key missing — Safe Browsing will fail.")
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {"clientId": "phishx", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", 
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        print("📬 Google Safe Browsing response code:", response.status_code)
        if response.status_code == 200:
            result = response.json()
            print("🛡️ Google Safe Browsing result:", result)
            return not result.get("matches")
        else:
            print("⚠️ Safe Browsing API failed:", response.status_code)
            return False
    except Exception as e:
        print("❌ Exception calling Safe Browsing API:", e)
        return False

def check_phishtank_csv(url):
    phishtank_csv_url = "https://data.phishtank.com/data/online-valid.csv"
    response = requests.get(phishtank_csv_url)
    lines = response.text.splitlines()
    reader = csv.DictReader(lines)
    for row in reader:
        if url.strip().lower() == row["url"].strip().lower():
            print("⚠️ Found in PhishTank:", row["url"])
            return False
    return True


def domain_exists(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        socket.gethostbyname(domain)
        print(f"🌐 Domain exists: {domain}")
        return True
    except Exception as e:
        print(f"❌ Domain resolution failed: {url} →{e}")
        return False


