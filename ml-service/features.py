import math
import re
import tldextract
from collections import Counter
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update",
    "account", "banking", "signin", "confirm",
    "wallet", "alert", "password", "recover",
    "support", "auth", "payment", "invoice"
]

HIGH_RISK_TLDS = [
    "xyz", "top", "gq", "tk", "ml",
    "cf", "ga", "work", "click", "buzz",
    "monster", "loan", "vip", "country"
]

SHORTENERS = [
    "bit.ly", "tinyurl", "goo.gl",
    "t.co", "is.gd", "rb.gy", "cutt.ly"
]

TRUSTED_BRANDS = [
    "google", "amazon", "paypal", "facebook",
    "instagram", "microsoft", "netflix",
    "github", "apple", "linkedin", "openai"
]


def calculate_entropy(text):
    if not text:
        return 0

    counter = Counter(text)
    length = len(text)

    entropy = 0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def has_ip_address(url):
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(ip_pattern, url) else 0


def suspicious_word_count(url):
    url = url.lower()
    return sum(word in url for word in SUSPICIOUS_WORDS)


def high_risk_tld_score(suffix):
    return 1 if suffix.lower() in HIGH_RISK_TLDS else 0


def shortener_score(url):
    url = url.lower()
    return 1 if any(short in url for short in SHORTENERS) else 0


def brand_abuse_score(domain, url):
    url = url.lower()
    domain = domain.lower()

    score = 0

    for brand in TRUSTED_BRANDS:
        if brand in url and brand not in domain:
            score += 1

    return score


def repeated_char_score(url):
    matches = re.findall(r"(.)\1{2,}", url.lower())
    return len(matches)


def numeric_domain_score(domain):
    return sum(c.isdigit() for c in domain)


def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    domain = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix

    features = [
        len(url),                                      # 1
        len(domain),                                   # 2
        subdomain.count('.') + (1 if subdomain else 0),  # 3
        sum(c.isdigit() for c in url),                 # 4
        url.count('-'),                                # 5
        url.count('.'),                                # 6
        1 if parsed.scheme == "https" else 0,          # 7
        has_ip_address(url),                           # 8
        1 if "@" in url else 0,                        # 9
        suspicious_word_count(url),                    # 10
        calculate_entropy(url),                        # 11
        high_risk_tld_score(suffix),                   # 12
        len(parsed.path),                              # 13
        len(parsed.query),                             # 14
        shortener_score(url),                          # 15
        brand_abuse_score(domain, url),                # 16
        repeated_char_score(url),                      # 17
        numeric_domain_score(domain)                   # 18
    ]

    return features