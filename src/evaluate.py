"""
Evaluate the saved model on any labelled CSV (columns: url,label).

Run:  python -m src.evaluate --data data/raw/dataset.csv
"""
from __future__ import annotations

import argparse

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

import config
from src.data_loader import clean_dataframe
from src.feature_extraction import features_to_frame


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the trained model on a CSV file.")
    parser.add_argument("--data", required=True)
    parser.add_argument("--model", default=str(config.MODEL_PATH))
    args = parser.parse_args()

    artifact = joblib.load(args.model)
    df = clean_dataframe(pd.read_csv(args.data))
    pred = artifact["model"].predict(features_to_frame(df["url"]))

    print(f"Model: {artifact['model_name']} | {len(df)} URLs\n")
    print(classification_report(df["label"], pred, target_names=["legitimate", "phishing"], digits=3))
    print("Confusion matrix [[TN FP] [FN TP]]:")
    print(confusion_matrix(df["label"], pred))


if __name__ == "__main__":
    main()
