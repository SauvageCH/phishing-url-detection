"""
Optional: build a REAL dataset from free public sources.

- Phishing URLs : OpenPhish community feed  (free, no account)
- Legitimate    : Tranco top sites list     (free, research-grade ranking)

The result is written to data/raw/dataset.csv, which train.py then uses
automatically instead of the synthetic data.

Run:  python -m src.download_data --max-per-class 5000

Needs internet access. If a source is unreachable, download the files by hand
(see docs/DATASET.md) and build the CSV yourself (columns: url,label).
"""
from __future__ import annotations

import argparse
import io
import random
import urllib.request
import zipfile

import pandas as pd

import config

OPENPHISH_URL = "https://openphish.com/feed.txt"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
COMMON_PATHS = ["", "", "", "/", "/about", "/contact", "/login", "/products",
                "/search?q=news", "/blog", "/help", "/pricing", "/account"]


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "phishing-detector-student-project"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def get_phishing(limit: int) -> list[str]:
    text = _fetch(OPENPHISH_URL).decode("utf-8", errors="ignore")
    urls = [line.strip() for line in text.splitlines() if line.strip().startswith("http")]
    return urls[:limit]


def get_legit(limit: int, seed: int) -> list[str]:
    raw = _fetch(TRANCO_URL)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        with zf.open(zf.namelist()[0]) as fh:
            ranking = pd.read_csv(fh, header=None, names=["rank", "domain"], nrows=limit * 3)
    rng = random.Random(seed)
    domains = ranking["domain"].sample(n=min(limit, len(ranking)), random_state=seed).tolist()
    # Real phishing URLs usually have a path, so legitimate ones get a plausible
    # path too; otherwise the model would just learn "has a path => phishing".
    return [f"https://{'www.' if rng.random() < 0.5 else ''}{d}{rng.choice(COMMON_PATHS)}" for d in domains]


def main() -> None:
    parser = argparse.ArgumentParser(description="Download a real phishing/legit URL dataset.")
    parser.add_argument("--max-per-class", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=config.RANDOM_SEED)
    args = parser.parse_args()

    print("Downloading phishing URLs from OpenPhish ...")
    phish = get_phishing(args.max_per_class)
    print(f"  got {len(phish)}")
    print("Downloading legitimate domains from Tranco ...")
    legit = get_legit(max(len(phish), 1), args.seed)
    print(f"  got {len(legit)}")

    df = pd.DataFrame({"url": phish + legit,
                       "label": [config.LABEL_PHISHING] * len(phish) + [config.LABEL_LEGIT] * len(legit)})
    df = df.sample(frac=1, random_state=args.seed).reset_index(drop=True)
    config.RAW_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(config.RAW_DATASET, index=False)
    print(f"Saved {len(df)} rows to {config.RAW_DATASET}")


if __name__ == "__main__":
    main()
