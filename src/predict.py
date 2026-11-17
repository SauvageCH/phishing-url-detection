"""
Inference: one URL in, a full analysis out.

    from src.predict import PhishingDetector
    detector = PhishingDetector()
    detector.analyze("http://paypal.secure-login.xyz/verify")
"""
from __future__ import annotations

from pathlib import Path

import joblib

import config
from src.explain import red_flags
from src.feature_extraction import extract_features, features_to_frame, parse_url


class ModelNotFoundError(FileNotFoundError):
    pass


class PhishingDetector:
    def __init__(self, model_path: str | Path = config.MODEL_PATH):
        model_path = Path(model_path)
        if not model_path.exists():
            raise ModelNotFoundError(
                f"No trained model at {model_path}. Run:  python -m src.train")
        self._path = model_path
        artifact = joblib.load(model_path)
        self.model = artifact["model"]
        self.info = {k: v for k, v in artifact.items() if k not in ("model", "feature_names")}

    @staticmethod
    def risk_level(p: float) -> str:
        if p < config.RISK_LOW_MAX:
            return "low"
        if p < config.RISK_MEDIUM_MAX:
            return "medium"
        return "high"

    def analyze(self, url: str) -> dict:
        url = (url or "").strip()
        if not url:
            raise ValueError("Please enter a URL.")
        if len(url) > config.MAX_URL_LENGTH:
            raise ValueError(f"URL is too long (max {config.MAX_URL_LENGTH} characters).")

        parts = parse_url(url)
        if not parts["host"]:
            raise ValueError("This does not look like a valid URL.")

        proba = float(self.model.predict_proba(features_to_frame([url]))[0][1])
        is_phishing = proba >= config.THRESHOLD
        return {
            "url": parts["url"],
            "verdict": "phishing" if is_phishing else "legitimate",
            "probability_phishing": round(proba, 4),
            "confidence": round(proba if is_phishing else 1 - proba, 4),
            "risk_level": self.risk_level(proba),
            "red_flags": red_flags(url),
            "parts": {k: parts[k] for k in ("scheme", "subdomain", "domain", "suffix", "path", "query")},
            "features": extract_features(url),
        }
