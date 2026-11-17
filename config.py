"""Central configuration: every path and constant lives here."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

# A real dataset (columns: url,label) dropped here is used automatically.
RAW_DATASET = RAW_DIR / "dataset.csv"
# Used when no real dataset is available.
SYNTHETIC_DATASET = PROCESSED_DIR / "synthetic_dataset.csv"

MODEL_PATH = MODELS_DIR / "model.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"

RANDOM_SEED = 42
TEST_SIZE = 0.2
CV_FOLDS = 5
SYNTHETIC_SAMPLES = 8000

# Label encoding used everywhere in the project
LABEL_LEGIT = 0
LABEL_PHISHING = 1

# Decision threshold on P(phishing) and risk bands shown in the UI
THRESHOLD = 0.5
RISK_LOW_MAX = 0.35
RISK_MEDIUM_MAX = 0.65

MAX_URL_LENGTH = 2048
