"""
Model training.

Pipeline:
 1. load the dataset (real if present, otherwise synthetic)
 2. extract features from every URL
 3. stratified train/test split
 4. compare 3 algorithms with cross-validation on the TRAIN part only
 5. refit the best one, evaluate once on the untouched TEST part
 6. save model + metrics + charts

Run:  python -m src.train
      python -m src.train --data data/raw/dataset.csv
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

import config
from src.data_loader import load_dataset
from src.feature_extraction import FEATURE_NAMES, features_to_frame


def candidate_models(seed: int) -> dict:
    return {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=seed)),
        "Random Forest": RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=seed),
        "Gradient Boosting": HistGradientBoostingClassifier(random_state=seed),
    }


def compute_metrics(y_true, y_pred, y_proba) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred)), 4),
        "recall": round(float(recall_score(y_true, y_pred)), 4),
        "f1": round(float(f1_score(y_true, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_proba)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def save_charts(model, y_test, y_pred, reports_dir: Path) -> None:
    """Confusion matrix + feature importance. Skipped silently without matplotlib."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed: skipping charts.")
        return

    reports_dir.mkdir(parents=True, exist_ok=True)
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], ["Legit", "Phishing"])
    ax.set_yticks([0, 1], ["Legit", "Phishing"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion matrix (test set)")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, int(v), ha="center", va="center", color="white" if v > cm.max() / 2 else "black")
    fig.tight_layout()
    fig.savefig(reports_dir / "confusion_matrix.png", dpi=150)
    plt.close(fig)

    importances = getattr(model, "feature_importances_", None)
    if importances is None and hasattr(model, "named_steps"):
        coef = getattr(model.steps[-1][1], "coef_", None)
        importances = np.abs(coef[0]) if coef is not None else None
    if importances is not None:
        order = np.argsort(importances)[-15:]
        fig, ax = plt.subplots(figsize=(6, 5))
        ax.barh([FEATURE_NAMES[i] for i in order], np.asarray(importances)[order], color="#12507A")
        ax.set_title("Top 15 features")
        fig.tight_layout()
        fig.savefig(reports_dir / "feature_importance.png", dpi=150)
        plt.close(fig)


def train(df, models_dir: Path = config.MODELS_DIR, reports_dir: Path = config.REPORTS_DIR,
          seed: int = config.RANDOM_SEED, test_size: float = config.TEST_SIZE,
          source: str = "unknown", verbose: bool = True) -> dict:
    log = print if verbose else (lambda *a, **k: None)

    log(f"Extracting features from {len(df)} URLs ...")
    X = features_to_frame(df["url"])
    y = df["label"].to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=seed)

    cv = StratifiedKFold(n_splits=config.CV_FOLDS, shuffle=True, random_state=seed)
    cv_scores = {}
    for name, model in candidate_models(seed).items():
        score = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
        cv_scores[name] = round(float(score.mean()), 4)
        log(f"  CV F1  {name:<20} {score.mean():.4f} (+/- {score.std():.4f})")

    best_name = max(cv_scores, key=cv_scores.get)
    best = candidate_models(seed)[best_name]
    best.fit(X_train, y_train)
    log(f"Best model: {best_name}")

    y_pred = best.predict(X_test)
    y_proba = best.predict_proba(X_test)[:, 1]
    metrics = compute_metrics(y_test, y_pred, y_proba)
    log("Test metrics:", {k: v for k, v in metrics.items() if k != "confusion_matrix"})

    # Final model is refit on ALL data so the app uses every example.
    final = candidate_models(seed)[best_name]
    final.fit(X, y)

    models_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": final,
        "model_name": best_name,
        "feature_names": FEATURE_NAMES,
        "metrics": metrics,
        "cv_f1": cv_scores,
        "data_source": source,
        "n_samples": int(len(df)),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    joblib.dump(artifact, models_dir / "model.joblib")
    summary = {k: v for k, v in artifact.items() if k not in ("model", "feature_names")}
    (models_dir / "metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    save_charts(best, y_test, y_pred, reports_dir)
    log(f"Saved model to {models_dir / 'model.joblib'}")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the phishing URL classifier.")
    parser.add_argument("--data", default=None, help="CSV with columns url,label")
    parser.add_argument("--n-synthetic", type=int, default=config.SYNTHETIC_SAMPLES)
    parser.add_argument("--seed", type=int, default=config.RANDOM_SEED)
    args = parser.parse_args()

    df, source = load_dataset(args.data, args.n_synthetic)
    print(f"Dataset: {source} | {len(df)} URLs | phishing share {df.label.mean():.0%}")
    train(df, seed=args.seed, source=source)


if __name__ == "__main__":
    main()
