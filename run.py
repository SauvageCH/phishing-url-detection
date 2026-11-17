"""
Launch the web app:   python run.py

If no trained model exists yet, one is trained automatically (about 30 s,
on the built-in synthetic dataset or on data/raw/dataset.csv if you added it).
"""
import argparse

import config
from app.app import create_app


def ensure_model() -> None:
    if config.MODEL_PATH.exists():
        return
    print("No trained model found: training one now ...")
    from src.data_loader import load_dataset
    from src.train import train

    df, source = load_dataset()
    train(df, source=source)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    ensure_model()
    create_app().run(host=args.host, port=args.port, debug=args.debug)
