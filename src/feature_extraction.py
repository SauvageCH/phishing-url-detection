"""
URL feature extraction.

Turns a raw URL string into a fixed-length numeric vector that a Machine
Learning model can use. Everything here is *lexical*: the URL is analysed as
text only. We never open the link, never query DNS or WHOIS, so the whole
pipeline is free, fast, offline and safe to run on dangerous links.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

import pandas as pd

# --------------------------------------------------------------------------- #
# Knowledge lists (small on purpose, easy to extend)
# --------------------------------------------------------------------------- #
SUSPICIOUS_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "banking", "password", "passwd", "wallet",
    "billing", "payment", "suspend", "unlock", "recover", "validate", "webscr",
    "support", "alert", "authenticate", "credential",
)

BRANDS = (
    "paypal", "google", "apple", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "twitter", "dropbox", "adobe", "ebay",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "dhl", "fedex",
    "usps", "outlook", "office365", "icloud", "steam", "binance", "coinbase",
    "spotify", "att", "verizon",
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "support",
    "zip", "country", "kim", "loan", "men", "review", "stream", "download",
    "racing", "win", "bid", "party", "science", "cam", "icu", "monster", "rest",
}

# Public suffixes made of two labels (tiny subset, avoids the `tldextract` dependency)
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "ne.jp", "co.in", "com.br", "com.mx", "com.tr",
    "co.za", "com.cn", "com.sg", "com.ar", "co.ma", "com.eg",
}

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

# Order matters: this is the column order the model is trained on.
FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "count_dots", "count_hyphens_host", "count_hyphens_url", "count_underscores",
    "count_at", "count_question", "count_equals", "count_ampersand",
    "count_percent", "count_slashes", "count_digits", "digit_ratio",
    "special_char_ratio", "has_ip_host", "is_https", "has_port",
    "subdomain_count", "domain_length", "domain_has_digits", "domain_has_hyphen",
    "is_suspicious_tld", "is_shortener", "keyword_count", "keyword_in_host",
    "host_entropy", "url_entropy", "has_punycode", "double_slash_in_path",
    "path_depth", "longest_host_token", "brand_in_subdomain_or_path",
    "brand_in_domain_not_exact", "is_typosquat", "has_userinfo",
    "has_hex_encoding", "file_extension_suspicious",
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def shannon_entropy(text: str) -> float:
    """Randomness of a string. Machine-generated names score higher."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def normalize_url(url: str) -> str:
    """Strip whitespace and add https:// when the user typed no scheme."""
    url = (url or "").strip()
    if not SCHEME_RE.match(url):
        url = "https://" + url.lstrip("/")
    return url


def parse_url(url: str) -> dict:
    """Split a URL into the parts we reason about."""
    url = normalize_url(url)
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = None
    except ValueError:  # malformed IPv6 literal etc.
        parts, host, port = urlsplit("https://invalid"), "", None

    userinfo = "@" in (parts.netloc or "")
    subdomain, domain, suffix = "", host, ""

    if host and not IP_RE.match(host):
        labels = host.split(".")
        last_two = ".".join(labels[-2:])
        if len(labels) >= 3 and last_two in MULTI_PART_SUFFIXES:
            suffix, domain = last_two, labels[-3]
            subdomain = ".".join(labels[:-3])
        elif len(labels) >= 2:
            suffix, domain = labels[-1], labels[-2]
            subdomain = ".".join(labels[:-2])
        else:
            domain = labels[0]

    return {
        "url": url,
        "scheme": parts.scheme.lower(),
        "host": host,
        "port": port,
        "subdomain": subdomain,
        "domain": domain,
        "suffix": suffix,
        "path": parts.path or "",
        "query": parts.query or "",
        "has_userinfo": userinfo,
        "is_ip": bool(IP_RE.match(host)),
    }


def _deleet(text: str) -> str:
    """Undo common look-alike swaps: paypa1 -> paypal, g00gle -> google."""
    return text.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"}))


def _within_one_edit(a: str, b: str) -> bool:
    """True if two strings differ by at most one insert/delete/replace."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = diffs = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        diffs += 1
        if diffs > 1:
            return False
        if len(a) == len(b):
            i += 1
        j += 1
    return True


def detect_typosquat(domain: str) -> str | None:
    """Return the brand a domain imitates (not equal to), else None."""
    if not domain:
        return None
    for brand in BRANDS:
        if domain == brand:
            return None
    for brand in BRANDS:
        if len(brand) < 5:
            continue
        if _deleet(domain) == brand or _within_one_edit(domain, brand):
            return brand
    return None


# --------------------------------------------------------------------------- #
# Main API
# --------------------------------------------------------------------------- #
def extract_features(url: str) -> dict:
    """Return {feature_name: number} for a single URL."""
    p = parse_url(url)
    full, host, path, query = p["url"], p["host"], p["path"], p["query"]
    domain, subdomain = p["domain"], p["subdomain"]
    lowered = full.lower()

    n = max(len(full), 1)
    digits = sum(ch.isdigit() for ch in full)
    specials = sum(not ch.isalnum() for ch in full)
    registered = f"{domain}.{p['suffix']}" if p["suffix"] else domain

    keyword_count = sum(lowered.count(k) for k in SUSPICIOUS_KEYWORDS)
    keyword_in_host = int(any(k in host for k in SUSPICIOUS_KEYWORDS))

    sub_path = f"{subdomain}.{path}.{query}".lower()
    brand_in_sub_or_path = int(any(b in sub_path and b != domain for b in BRANDS))
    brand_in_domain_not_exact = int(
        any(b in domain and b != domain for b in BRANDS) and not p["is_ip"]
    )

    last_segment = path.rsplit("/", 1)[-1].lower()
    ext = last_segment.rsplit(".", 1)[-1] if "." in last_segment else ""

    return {
        "url_length": len(full),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "count_dots": host.count("."),
        "count_hyphens_host": host.count("-"),
        "count_hyphens_url": full.count("-"),
        "count_underscores": full.count("_"),
        "count_at": full.count("@"),
        "count_question": full.count("?"),
        "count_equals": full.count("="),
        "count_ampersand": full.count("&"),
        "count_percent": full.count("%"),
        "count_slashes": full.count("/"),
        "count_digits": digits,
        "digit_ratio": digits / n,
        "special_char_ratio": specials / n,
        "has_ip_host": int(p["is_ip"]),
        "is_https": int(p["scheme"] == "https"),
        "has_port": int(p["port"] not in (None, 80, 443)),
        "subdomain_count": len([s for s in subdomain.split(".") if s]),
        "domain_length": len(domain),
        "domain_has_digits": int(any(c.isdigit() for c in domain) and not p["is_ip"]),
        "domain_has_hyphen": int("-" in domain),
        "is_suspicious_tld": int(p["suffix"].split(".")[-1] in SUSPICIOUS_TLDS),
        "is_shortener": int(registered in SHORTENERS),
        "keyword_count": keyword_count,
        "keyword_in_host": keyword_in_host,
        "host_entropy": shannon_entropy(host),
        "url_entropy": shannon_entropy(full),
        "has_punycode": int("xn--" in host),
        "double_slash_in_path": int("//" in path),
        "path_depth": len([s for s in path.split("/") if s]),
        "longest_host_token": max((len(t) for t in re.split(r"[.\-]", host) if t), default=0),
        "brand_in_subdomain_or_path": brand_in_sub_or_path,
        "brand_in_domain_not_exact": brand_in_domain_not_exact,
        "is_typosquat": int(detect_typosquat(domain) is not None),
        "has_userinfo": int(p["has_userinfo"]),
        "has_hex_encoding": int(bool(re.search(r"%[0-9a-fA-F]{2}", full))),
        "file_extension_suspicious": int(ext in {"php", "exe", "zip", "scr", "js", "apk", "asp", "cgi"}),
    }


def features_to_frame(urls) -> pd.DataFrame:
    """Vectorise many URLs into a DataFrame with the exact training columns."""
    rows = [extract_features(u) for u in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)
