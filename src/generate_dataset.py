"""
Synthetic URL dataset generator.

Why: the project must work immediately and for $0, without registering on
any website. This script fabricates realistic *legitimate* and *phishing*
URLs following the patterns documented in the phishing literature
(brand in subdomain, typosquatting, IP hosts, '@' trick, free hosting...).

IMPORTANT: synthetic data is for the demo and for testing the pipeline.
Scores obtained on it are optimistic. For a serious evaluation, use real
data (see docs/DATASET.md and src/download_data.py).

Run:  python -m src.generate_dataset --n 8000
"""
from __future__ import annotations

import argparse
import random
import string

import pandas as pd

import config

LEGIT_SITES = [
    ("google", "com"), ("youtube", "com"), ("facebook", "com"), ("wikipedia", "org"),
    ("amazon", "com"), ("amazon", "co.uk"), ("apple", "com"), ("microsoft", "com"),
    ("github", "com"), ("stackoverflow", "com"), ("reddit", "com"), ("linkedin", "com"),
    ("netflix", "com"), ("twitter", "com"), ("instagram", "com"), ("paypal", "com"),
    ("ebay", "com"), ("bbc", "co.uk"), ("nytimes", "com"), ("cnn", "com"),
    ("python", "org"), ("mozilla", "org"), ("adobe", "com"), ("dropbox", "com"),
    ("spotify", "com"), ("medium", "com"), ("coursera", "org"), ("udemy", "com"),
    ("openai", "com"), ("cloudflare", "com"), ("nasa", "gov"), ("mit", "edu"),
    ("harvard", "edu"), ("lemonde", "fr"), ("leboncoin", "fr"), ("orange", "fr"),
    ("hespress", "com"), ("onmsi", "ma"), ("um5", "ac.ma"), ("cdiscount", "com"),
    ("booking", "com"), ("airbnb", "com"), ("whatsapp", "com"), ("zoom", "us"),
    ("slack", "com"), ("notion", "so"), ("figma", "com"), ("kaggle", "com"),
    ("w3schools", "com"), ("imdb", "com"), ("steamcommunity", "com"), ("chase", "com"),
    ("wellsfargo", "com"), ("hsbc", "com"), ("dhl", "com"), ("fedex", "com"),
]
LEGIT_SUBDOMAINS = ["www", "www", "www", "docs", "mail", "support", "blog", "shop",
                    "en", "fr", "news", "help", "developer", "accounts", "m", "app"]
PATH_WORDS = ["about", "products", "search", "news", "blog", "help", "docs", "pricing",
              "contact", "careers", "download", "watch", "wiki", "article", "category",
              "tutorial", "events", "store", "community", "terms", "privacy", "login",
              "account", "settings", "signin", "support", "reviews", "forum", "learn"]
SLUG_WORDS = ["how", "to", "learn", "python", "in", "30", "days", "best", "free", "guide",
              "top", "10", "tips", "for", "students", "new", "release", "notes", "2025", "2026"]
QUERY_KEYS = ["q", "id", "page", "ref", "lang", "utm_source", "sort", "v", "tab", "s"]

BRANDS = ["paypal", "google", "apple", "microsoft", "amazon", "netflix", "facebook",
          "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "ebay", "chase",
          "wellsfargo", "bankofamerica", "hsbc", "dhl", "fedex", "outlook", "icloud",
          "coinbase", "binance", "spotify", "steam"]
KEYWORDS = ["login", "secure", "verify", "account", "update", "signin", "confirm",
            "support", "billing", "password", "wallet", "recover", "security", "alert"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link",
            "icu", "cam", "info", "online", "site", "club", "shop", "live", "buzz"]
OK_TLDS = ["com", "net", "org", "info", "co"]
FREE_HOSTS = ["000webhostapp.com", "weebly.com", "blogspot.com", "firebaseapp.com",
              "web.app", "glitch.me", "netlify.app", "wixsite.com", "github.io"]
PHISH_PATHS = ["login", "signin", "verify", "update", "secure", "account/confirm",
               "webscr", "auth/session", "recover", "wp-includes/login", "index",
               "validate", "billing/update", "myaccount/security"]
FILLER = ["data", "cloud", "portal", "service", "online", "center", "web", "mail",
          "net", "app", "pay", "bank", "home", "team", "hub", "pro"]


def _rand_token(rng: random.Random, n: int) -> str:
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=n))


def _rand_word_domain(rng: random.Random) -> str:
    return rng.choice(FILLER) + rng.choice(FILLER) + (str(rng.randint(1, 99)) if rng.random() < 0.3 else "")


# ------------------------------- legitimate -------------------------------- #
def make_legit(rng: random.Random) -> str:
    domain, suffix = rng.choice(LEGIT_SITES)
    r = rng.random()
    if r < 0.15:
        host = f"{domain}.{suffix}"
    elif r < 0.85:
        host = f"{rng.choice(LEGIT_SUBDOMAINS)}.{domain}.{suffix}"
    else:
        host = f"{rng.choice(LEGIT_SUBDOMAINS)}.{rng.choice(LEGIT_SUBDOMAINS)}.{domain}.{suffix}"
    scheme = "https" if rng.random() < 0.93 else "http"

    segments = []
    for _ in range(rng.choices([0, 1, 2, 3, 4], weights=[25, 30, 25, 15, 5])[0]):
        c = rng.random()
        if c < 0.55:
            segments.append(rng.choice(PATH_WORDS))
        elif c < 0.80:
            segments.append("-".join(rng.sample(SLUG_WORDS, k=rng.randint(2, 6))))
        else:
            segments.append(str(rng.randint(1, 99999999)))
    path = "/" + "/".join(segments) if segments else ""
    if segments and rng.random() < 0.15:
        path += rng.choice([".html", ".htm", ".php", ".aspx"])
    elif not segments and rng.random() < 0.5:
        path = "/"

    query = ""
    if rng.random() < 0.3:
        query = "?" + "&".join(
            f"{rng.choice(QUERY_KEYS)}={rng.choice(PATH_WORDS + [str(rng.randint(1, 9999))])}"
            for _ in range(rng.randint(1, 3))
        )
    return f"{scheme}://{host}{path}{query}"


# -------------------------------- phishing --------------------------------- #
def _typo(rng: random.Random, brand: str) -> str:
    swaps = {"o": "0", "l": "1", "e": "3", "a": "4", "i": "1", "s": "5"}
    chars = list(brand)
    idx = [i for i, c in enumerate(chars) if c in swaps]
    if idx and rng.random() < 0.6:
        i = rng.choice(idx)
        chars[i] = swaps[chars[i]]
    else:
        i = rng.randrange(len(chars))
        op = rng.choice(["dup", "drop", "swap"])
        if op == "dup":
            chars.insert(i, chars[i])
        elif op == "drop" and len(chars) > 4:
            chars.pop(i)
        elif i < len(chars) - 1:
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
    return "".join(chars)


def make_phish(rng: random.Random) -> str:
    brand, kw, kw2 = rng.choice(BRANDS), rng.choice(KEYWORDS), rng.choice(KEYWORDS)
    tld = rng.choice(BAD_TLDS if rng.random() < 0.7 else OK_TLDS)
    scheme = "https" if rng.random() < 0.55 else "http"
    path = "/" + rng.choice(PHISH_PATHS)
    if rng.random() < 0.4:
        path += rng.choice([".php", ".html", ".asp"])
    if rng.random() < 0.35:
        path += f"?{rng.choice(['id', 'session', 'token', 'cmd'])}={_rand_token(rng, rng.randint(6, 24))}"

    pattern = rng.choices(
        ["brand_sub", "brand_hyphen", "ip", "typo", "at", "deep_sub",
         "free_host", "hacked_site", "random_domain", "punycode"],
        weights=[16, 18, 8, 12, 5, 8, 10, 10, 9, 4],
    )[0]

    if pattern == "brand_sub":
        host = f"{brand}.{kw}-{_rand_word_domain(rng)}.{tld}"
    elif pattern == "brand_hyphen":
        host = rng.choice([f"{brand}-{kw}.{tld}", f"{kw}-{brand}.{tld}",
                           f"{brand}-{kw}-{kw2}.{tld}", f"{brand}{kw}{rng.randint(1, 999)}.{tld}"])
    elif pattern == "ip":
        host = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        if rng.random() < 0.3:
            host += f":{rng.choice([8080, 8000, 8443, 3000])}"
        path = f"/{brand}" + path
    elif pattern == "typo":
        host = f"{_typo(rng, brand)}.{rng.choice(['com', 'net', tld])}"
        if rng.random() < 0.5:
            host = f"{rng.choice(['www', 'secure', 'my'])}.{host}"
    elif pattern == "at":
        legit_domain, legit_suffix = rng.choice(LEGIT_SITES)
        host = f"{legit_domain}.{legit_suffix}@{_rand_word_domain(rng)}.{tld}"
    elif pattern == "deep_sub":
        host = f"{kw}.{kw2}.{brand}.{_rand_word_domain(rng)}.{tld}"
    elif pattern == "free_host":
        host = f"{brand}-{kw}-{_rand_token(rng, rng.randint(3, 6))}.{rng.choice(FREE_HOSTS)}"
    elif pattern == "hacked_site":
        host = f"{_rand_word_domain(rng)}.{rng.choice(OK_TLDS)}"
        path = f"/wp-content/{brand}/{kw}" + rng.choice([".php", "/index.html", "/"])
    elif pattern == "random_domain":
        host = f"{_rand_token(rng, rng.randint(8, 16))}.{tld}"
    else:  # punycode
        host = f"xn--{_rand_token(rng, 5)}-{brand}.{rng.choice(['com', tld])}"

    return f"{scheme}://{host}{path}"


# --------------------------------- public ---------------------------------- #
def generate_dataset(n: int = config.SYNTHETIC_SAMPLES, seed: int = config.RANDOM_SEED,
                     label_noise: float = 0.02) -> pd.DataFrame:
    """Balanced dataset (50/50) with a little label noise so metrics stay realistic."""
    rng = random.Random(seed)
    rows, seen = [], set()
    half = n // 2
    for label, maker in ((config.LABEL_LEGIT, make_legit), (config.LABEL_PHISHING, make_phish)):
        count, tries = 0, 0
        while count < half and tries < half * 20:
            tries += 1
            url = maker(rng)
            if url in seen:
                continue
            seen.add(url)
            y = label
            if rng.random() < label_noise:
                y = 1 - label
            rows.append((url, y))
            count += 1
    rng.shuffle(rows)
    return pd.DataFrame(rows, columns=["url", "label"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic phishing/legit URL dataset.")
    parser.add_argument("--n", type=int, default=config.SYNTHETIC_SAMPLES)
    parser.add_argument("--seed", type=int, default=config.RANDOM_SEED)
    parser.add_argument("--out", default=str(config.SYNTHETIC_DATASET))
    args = parser.parse_args()

    df = generate_dataset(args.n, args.seed)
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Saved {len(df)} URLs to {args.out}")
    print(df.label.value_counts().rename({0: "legitimate", 1: "phishing"}).to_string())


if __name__ == "__main__":
    main()
