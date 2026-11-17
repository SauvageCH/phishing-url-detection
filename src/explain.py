"""
Human-readable explanations.

A prediction like "92% phishing" is not very useful on its own. This module
lists the concrete red flags found in a URL so a person can understand *why*.
These rules are for explanation only: the verdict itself comes from the ML model.
"""
from __future__ import annotations

from src.feature_extraction import (
    SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, detect_typosquat, extract_features, parse_url,
)

# severity: 3 = strong signal, 2 = moderate, 1 = weak
# part: which piece of the URL to highlight in the UI
def red_flags(url: str) -> list[dict]:
    p = parse_url(url)
    f = extract_features(url)
    flags: list[dict] = []

    def add(code, message, severity, part):
        flags.append({"code": code, "message": message, "severity": severity, "part": part})

    if f["has_ip_host"]:
        add("ip_host", "The address is a raw IP number instead of a domain name.", 3, "host")
    if f["has_userinfo"]:
        add("userinfo", "The URL contains '@', which can hide the real destination.", 3, "host")
    brand = detect_typosquat(p["domain"])
    if brand:
        add("typosquat", f"The domain '{p['domain']}' imitates the brand '{brand}'.", 3, "domain")
    if f["has_punycode"]:
        add("punycode", "The host uses punycode (xn--), often used for look-alike characters.", 3, "host")
    if f["brand_in_subdomain_or_path"]:
        add("brand_misuse", "A well-known brand name appears in the subdomain or path, not in the real domain.", 3, "subdomain")
    if f["brand_in_domain_not_exact"]:
        add("brand_in_domain", "The domain embeds a brand name with extra words.", 2, "domain")
    if f["is_suspicious_tld"]:
        add("bad_tld", f"The '.{p['suffix']}' extension is frequently abused in phishing.", 2, "suffix")
    if f["keyword_count"] >= 2 or f["keyword_in_host"]:
        found = sorted({k for k in SUSPICIOUS_KEYWORDS if k in p["url"].lower()})[:4]
        add("keywords", f"Urgent or credential-related words found: {', '.join(found)}.", 2, "path")
    if f["subdomain_count"] >= 3:
        add("many_subdomains", f"{f['subdomain_count']} subdomain levels: unusually deep.", 2, "subdomain")
    if f["count_hyphens_host"] >= 2:
        add("many_hyphens", "The host name contains several hyphens.", 1, "host")
    if f["url_length"] > 90:
        add("long_url", f"The URL is long ({f['url_length']} characters).", 1, "path")
    if not f["is_https"]:
        add("no_https", "The connection is not encrypted (http, not https).", 1, "scheme")
    if f["has_port"]:
        add("odd_port", "The URL uses a non-standard port.", 2, "host")
    if f["is_shortener"]:
        add("shortener", "A link shortener hides the final destination.", 2, "host")
    if f["host_entropy"] > 3.6 and f["host_length"] > 12:
        add("random_host", "The host name looks random or machine-generated.", 1, "host")
    if f["double_slash_in_path"]:
        add("double_slash", "A '//' inside the path can be a redirection trick.", 1, "path")
    if f["file_extension_suspicious"]:
        add("risky_file", "The link points to a script or downloadable file type.", 1, "path")

    flags.sort(key=lambda x: -x["severity"])
    return flags
