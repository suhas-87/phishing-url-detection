"""
PhishGuard - Dataset Generator
Generates a realistic, balanced dataset of legitimate and phishing URLs for training and evaluation.
Labels:
  0 = Legitimate / Safe
  1 = Phishing / Malicious
"""

import csv
import os
import random

# Fix random seed for reproducibility
random.seed(42)

LEGITIMATE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
    "amazon.com", "reddit.com", "netflix.com", "microsoft.com", "apple.com",
    "twitter.com", "linkedin.com", "instagram.com", "github.com", "stackoverflow.com",
    "medium.com", "bing.com", "cnn.com", "bbc.com", "nytimes.com",
    "stanford.edu", "mit.edu", "harvard.edu", "berkeley.edu", "ox.ac.uk",
    "cam.ac.uk", "nih.gov", "nasa.gov", "who.int", "cdc.gov",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com", "paypal.com",
    "dropbox.com", "spotify.com", "zoom.us", "salesforce.com", "adobe.com",
    "cloudflare.com", "slack.com", "notion.so", "figma.com", "canva.com",
    "quora.com", "twitch.tv", "imdb.com", "pinterest.com", "ebay.com",
    "walmart.com", "target.com", "bestbuy.com", "craigslist.org", "etsy.com",
    "forbes.com", "bloomberg.com", "reuters.com", "theverge.com", "techcrunch.com",
    "nationalgeographic.com", "britannica.com", "khanacademy.org", "coursera.org", "edx.org",
    "w3schools.com", "geeksforgeeks.org", "mozilla.org", "python.org", "apache.org",
    "oracle.com", "ibm.com", "intel.com", "cisco.com", "hp.com",
    "dell.com", "asus.com", "lenovo.com", "samsung.com", "sony.com"
]

LEGITIMATE_SUBDOMAINS = [
    "www", "docs", "support", "developer", "blog", "api", "portal", "account",
    "mail", "drive", "community", "help", "store", "news", "status"
]

LEGITIMATE_PATHS = [
    "",
    "/",
    "/about",
    "/contact-us",
    "/terms",
    "/privacy-policy",
    "/products",
    "/services",
    "/features",
    "/pricing",
    "/faq",
    "/blog/latest-news",
    "/documentation/getting-started",
    "/explore",
    "/search?q=machine+learning",
    "/wiki/Cybersecurity",
    "/wiki/Computer_science",
    "/learn/python-programming",
    "/user/profile",
    "/dashboard/overview",
    "/articles/technology-trends",
    "/download/latest-release",
    "/categories/education",
    "/press-release/2025/update",
    "/security/advisories"
]

TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citi", "facebook",
    "instagram", "securebank", "coinbase", "binance", "metamask",
    "dropbox", "dhl", "fedex", "usps", "irs-gov", "support-tech"
]

PHISHING_KEYWORDS = [
    "login", "verify", "account", "update", "secure", "bank",
    "signin", "confirm", "validation", "security", "credential",
    "billing", "service", "helpdesk", "recovery", "reactivate",
    "unlock", "alert", "portal", "auth"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".info", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".buzz", ".work", ".site", ".online", ".icu", ".cam", ".shop"
]

def generate_legitimate_urls(count=1500):
    urls = set()
    
    # 1. Base popular websites
    for domain in LEGITIMATE_DOMAINS:
        urls.add(f"https://{domain}")
        urls.add(f"https://www.{domain}")
        for path in LEGITIMATE_PATHS[:8]:
            urls.add(f"https://{domain}{path}")
            urls.add(f"https://www.{domain}{path}")

    # 2. Add realistic subdomains and deep paths
    while len(urls) < count:
        domain = random.choice(LEGITIMATE_DOMAINS)
        sub = random.choice(LEGITIMATE_SUBDOMAINS)
        path = random.choice(LEGITIMATE_PATHS)
        protocol = "https" if random.random() > 0.05 else "http"
        
        # Sometimes add realistic query params
        if random.random() > 0.6:
            query = f"?ref={random.choice(['home', 'nav', 'footer'])}&id={random.randint(100, 9999)}"
            url = f"{protocol}://{sub}.{domain}{path}{query}"
        else:
            url = f"{protocol}://{sub}.{domain}{path}"
        urls.add(url)

    url_list = list(urls)[:count]
    return [(url, 0) for url in url_list]

def generate_phishing_urls(count=1500):
    urls = set()

    # Pattern A: Raw IP address hosts (Classic Phishing)
    ip_patterns = [
        "http://192.168.{a}.{b}/{kw}/index.html",
        "http://45.33.{a}.{b}/{brand}-{kw}.php",
        "http://104.244.{a}.{b}/secure/signin.jsp",
        "http://185.220.{a}.{b}/{brand}/verify-account.htm",
        "http://203.0.113.{a}/{kw}/auth?session={rand}",
        "http://198.51.100.{a}:8080/bank/{kw}.php",
        "http://172.16.{a}.{b}/login-portal/confirm.html",
        "http://162.243.{a}.{b}/online-banking/{brand}.html"
    ]

    for _ in range(350):
        pat = random.choice(ip_patterns)
        url = pat.format(
            a=random.randint(1, 254),
            b=random.randint(1, 254),
            kw=random.choice(PHISHING_KEYWORDS),
            brand=random.choice(TARGET_BRANDS),
            rand=random.randint(100000, 999999)
        )
        urls.add(url)

    # Pattern B: Brand impersonation with hyphens & suspicious TLDs
    while len(urls) < 900:
        brand = random.choice(TARGET_BRANDS)
        kw1 = random.choice(PHISHING_KEYWORDS)
        kw2 = random.choice(PHISHING_KEYWORDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        proto = "http" if random.random() > 0.3 else "https"
        
        style = random.randint(1, 5)
        if style == 1:
            host = f"{brand}-{kw1}{tld}"
            path = f"/{kw2}"
        elif style == 2:
            host = f"{kw1}-{brand}-{kw2}{tld}"
            path = f"/account/login.php?client_id={random.randint(10000, 99999)}"
        elif style == 3:
            host = f"secure-{brand}-update{tld}"
            path = f"/{kw1}-verify?token={random.randint(1000000, 9999999)}"
        elif style == 4:
            host = f"{brand}.com.{kw1}-{kw2}{tld}"
            path = f"/auth/confirm-identity"
        else:
            host = f"{kw1}.{brand}{tld}"
            path = f"/webscr?cmd=_login-run&dispatch={random.randint(1000, 9999)}"
        
        urls.add(f"{proto}://{host}{path}")

    # Pattern C: Nested subdomain deception (e.g., paypal.com.account-update.xyz)
    while len(urls) < 1300:
        brand = random.choice(TARGET_BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        kw2 = random.choice(PHISHING_KEYWORDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        proto = "http" if random.random() > 0.4 else "https"
        
        url = (
            f"{proto}://{brand}.com.{kw}.{kw2}-access{tld}/"
            f"security/check?session={random.randint(10000, 99999)}"
            f"&verify=true&redirect=signin"
        )
        urls.add(url)

    # Pattern D: Excessively long URLs with symbol abuse (@, %, =, &)
    while len(urls) < count:
        brand = random.choice(TARGET_BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        proto = "http"
        
        # Adding suspicious tokens and query parameters
        token = "".join(random.choices("abcdef0123456789", k=24))
        user_fake = f"user_{random.randint(100, 999)}@fake-host.com"
        url = (
            f"{proto}://{kw}-{brand}-service{tld}/{kw}/submit.php"
            f"?user={user_fake}&session={token}&auth_key={token[:12]}&confirm=1"
        )
        urls.add(url)

    url_list = list(urls)[:count]
    return [(url, 1) for url in url_list]

def build_dataset(output_path="urls.csv", total_samples=3000):
    half = total_samples // 2
    print(f"Generating {half} legitimate URLs...")
    legit_data = generate_legitimate_urls(half)
    
    print(f"Generating {half} phishing URLs...")
    phish_data = generate_phishing_urls(half)
    
    combined = legit_data + phish_data
    random.shuffle(combined)
    
    print(f"Writing {len(combined)} samples to {output_path}...")
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url, label in combined:
            writer.writerow([url, label])
            
    print("Dataset generation complete!")
    print(f"File: {output_path}")
    print(f"Total samples: {len(combined)} (Legitimate: {len(legit_data)}, Phishing: {len(phish_data)})")

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    target_csv = os.path.join(current_dir, "urls.csv")
    build_dataset(target_csv, total_samples=3200)
