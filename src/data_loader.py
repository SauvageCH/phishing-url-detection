"""
Dataset loading and cleaning.

Priority:
1. data/raw/dataset.csv  (your real dataset, columns: url,label)
2. otherwise a synthetic dataset is generated and cached.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

import config
from src.generate_dataset import generate_dataset

PHISHING_WORDS = {"1", "phishing", "phish", "bad", "malicious", "malware", "defacement", "-1"}
LEGIT_WORDS = {"0", "legitimate", "legit", "benign", "good", "safe"}


def _to_binary(value) -> int | None:
    text = str(value).strip().lower()
    if text in PHISHING_WORDS:
        return config.LABEL_PHISHING
    if text in LEGIT_WORDS:
        return config.LABEL_LEGIT
    return None


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Keep ['url','label'], map labels to 0/1, drop empties and duplicates."""
    df = df.rename(columns={c: c.strip().lower() for c in df.columns})
    if "url" not in df.columns:
        raise ValueError("The dataset needs a 'url' column.")
    label_col = next((c for c in ("label", "class", "type", "status", "result") if c in df.columns), None)
    if label_col is None:
        raise ValueError("The dataset needs a 'label' column (0/1 or legitimate/phishing).")

    out = pd.DataFrame({"url": df["url"].astype(str).str.strip(),
                        "label": df[label_col].map(_to_binary)})
    out = out.dropna().query("url != ''").drop_duplicates(subset="url")
    out["label"] = out["label"].astype(int)
    return out.reset_index(drop=True)


def load_dataset(path: str | Path | None = None, n_synthetic: int = config.SYNTHETIC_SAMPLES):
    """Return (DataFrame, human-readable source description)."""
    path = Path(path) if path else config.RAW_DATASET
    if path.exists():
        df = clean_dataframe(pd.read_csv(path))
        return df, f"real dataset: {path.name}"

    df = generate_dataset(n_synthetic)
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(config.SYNTHETIC_DATASET, index=False)
    return df, "synthetic dataset (demo mode)"
