# AI-Based Phishing URL Detection System

> A machine-learning application that analyses a URL and decides whether it is **phishing** or **legitimate**, explains *why*, and runs entirely on your laptop for **$0**.

![python](https://img.shields.io/badge/python-3.10%2B-blue) ![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange) ![flask](https://img.shields.io/badge/web-Flask-black) ![license](https://img.shields.io/badge/license-MIT-green)

---

## 1. What it does

1. You paste a URL in the web page (or call the JSON API).
2. The app extracts **40 lexical features** from the URL text (length, IP host, `@` trick, suspicious words, brand imitation, entropy ...).
3. A trained classifier (the best of Logistic Regression / Random Forest / Gradient Boosting) outputs a **phishing probability**.
4. The page shows a verdict, a risk meter, the URL split into parts with the suspicious parts underlined, and a list of human-readable warnings.

The link is **never opened**: only its text is analysed, so it is safe even for dangerous URLs and needs no paid API.

## 2. Why it is free

| Need | Free solution |
|------|---------------|
| ML | scikit-learn |
| Web | Flask + plain HTML/CSS/JS (no framework, no CDN, works offline) |
| Data | Built-in synthetic generator, or OpenPhish + Tranco (free, no account) |
| Hosting | Runs locally. Can be deployed on a free tier (Render, PythonAnywhere, Hugging Face Spaces) |

## 3. Project structure

```
phishing-url-detector/
├── README.md                  <- you are here
├── requirements.txt           <- Python dependencies
├── config.py                  <- paths, seed, thresholds (single source of truth)
├── run.py                     <- starts the web app (trains a model first if needed)
├── pytest.ini  .gitignore  LICENSE
│
├── src/                       <- the machine-learning code
│   ├── feature_extraction.py  <- URL -> 40 numeric features
│   ├── generate_dataset.py    <- synthetic dataset generator (demo mode)
│   ├── download_data.py       <- builds a REAL dataset (OpenPhish + Tranco)
│   ├── data_loader.py         <- loads / cleans any url,label CSV
│   ├── train.py               <- compares 3 models, saves the best + charts
│   ├── evaluate.py            <- evaluates the saved model on any CSV
│   ├── explain.py             <- human-readable red flags
│   └── predict.py             <- PhishingDetector.analyze(url)
│
├── app/                       <- the web application
│   ├── app.py                 <- Flask app factory + JSON API
│   ├── templates/index.html   <- page
│   └── static/{css,js}/       <- style.css, main.js
│
├── tests/                     <- pytest tests (features, pipeline, API)
├── docs/                      <- ARCHITECTURE, FEATURES, DATASET, API
├── data/{raw,processed}/      <- datasets (git-ignored, generated on demand)
├── models/                    <- model.joblib + metrics.json (git-ignored)
└── reports/                   <- confusion matrix & feature importance PNG
```

## 4. Quick start

Requirements: **Python 3.10+** and `pip`. Nothing else.

```bash
# 1. get the code
git clone https://github.com/<your-username>/phishing-url-detector.git
cd phishing-url-detector

# 2. create an isolated environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. install dependencies
pip install -r requirements.txt

# 4. launch the app (trains a model automatically on first run, ~30 s)
python run.py
```

Open **http://127.0.0.1:5000** in your browser.

Useful options: `python run.py --port 8000`, `python run.py --debug`.

## 5. Step-by-step workflow (what to show your teacher)

```bash
python -m src.generate_dataset      # 1. (optional) create the synthetic dataset
python -m src.train                 # 2. train + compare models, save model & charts
python -m src.evaluate --data data/processed/synthetic_dataset.csv   # 3. detailed report
pytest                              # 4. run the tests
python run.py                       # 5. start the web app
```

### Use real data (strongly recommended for your report)

```bash
python -m src.download_data --max-per-class 5000   # needs internet
python -m src.train                                 # uses data/raw/dataset.csv automatically
```

Or place your own CSV (`url,label`) at `data/raw/dataset.csv`. See [docs/DATASET.md](docs/DATASET.md).

## 6. Results

Training on the built-in synthetic dataset (8,000 URLs, 20 % held-out test set) gives roughly:

| Model | CV F1 |
|-------|-------|
| Logistic Regression | 0.974 |
| **Random Forest** | **0.975** |
| Gradient Boosting | 0.974 |

Test set: accuracy ≈ 0.98, precision ≈ 0.98, recall ≈ 0.98, ROC-AUC ≈ 0.99.

> ⚠️ **Be honest in your report:** synthetic data was produced by rules similar to the features, so these scores are *optimistic*. Re-train on real data and report those numbers instead. Charts are saved in `reports/` after each training.

## 7. API

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"url":"http://paypal.secure-login-update.xyz/signin.php"}'
```

Endpoints: `POST /api/analyze`, `GET /api/model`, `GET /api/health`. Details in [docs/API.md](docs/API.md).

## 8. Limitations

- Only the URL text is analysed: no page content, domain age, SSL certificate or reputation databases.
- A legitimate-looking URL on a hacked site can fool the model; a strange but harmless URL can be a false positive.
- Models age: phishing tactics evolve, so retrain on fresh data regularly.
- This is an educational tool, **not** a replacement for browser protection or a security product.

## 9. Ideas to go further

- Add WHOIS domain-age and DNS features, or the free Google Safe Browsing API.
- Character-level n-grams (TF-IDF) or a small CNN/LSTM on raw URL characters.
- Browser extension calling `/api/analyze`.
- Deploy on a free tier and add a Dockerfile.
- Probability calibration and threshold tuning to favour precision or recall.

## 10. Documentation

- [Architecture & design decisions](docs/ARCHITECTURE.md)
- [Feature reference](docs/FEATURES.md)
- [Datasets & biases](docs/DATASET.md)
- [HTTP API](docs/API.md)

## 11. Publish on GitHub

```bash
git init
git add .
git commit -m "Initial commit: AI-based phishing URL detector"
git branch -M main
git remote add origin https://github.com/<your-username>/phishing-url-detector.git
git push -u origin main
```

Models and datasets are git-ignored on purpose (they are regenerated in seconds).

## 12. License

MIT: see [LICENSE](LICENSE).
