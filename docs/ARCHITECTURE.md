# Architecture

## Big picture

```
            TRAINING (offline, once)                       SERVING (online)
 ┌────────────┐   ┌──────────────────┐   ┌─────────┐      ┌─────────────┐
 │ dataset    │──▶│ feature_extraction│──▶│ train.py│──▶ model.joblib ──▶ predict.py ──▶ Flask API ──▶ Browser
 │ (CSV)      │   │ 40 numeric values │   │ 3 models│                     │  + explain.py   /api/analyze    (HTML/JS)
 └────────────┘   └──────────────────┘   └─────────┘                     └─ same feature_extraction
```

The **same** `feature_extraction.py` is used for training and for serving. This is
important: if the two differed, the model would receive data it was never trained on
(training/serving skew).

## Modules

| File | Role |
|------|------|
| `config.py` | All paths and constants (seed, thresholds, split sizes). |
| `src/feature_extraction.py` | URL string -> 40 numbers. Pure Python, no network. |
| `src/generate_dataset.py` | Builds a synthetic labelled dataset (demo mode). |
| `src/download_data.py` | Builds a real dataset from OpenPhish + Tranco (optional). |
| `src/data_loader.py` | Loads and cleans a CSV; falls back to synthetic data. |
| `src/train.py` | Cross-validated model comparison, final training, saving, charts. |
| `src/evaluate.py` | Re-evaluates a saved model on any CSV. |
| `src/explain.py` | Rule-based red flags that explain a prediction to a human. |
| `src/predict.py` | `PhishingDetector.analyze(url)`: the single entry point for inference. |
| `app/app.py` | Flask factory + JSON API. |
| `app/templates`, `app/static` | The web page (HTML, CSS, vanilla JS). |
| `run.py` | Starts the app; trains a model first if none exists. |
| `tests/` | Unit and integration tests (pytest). |

## Training protocol (why the numbers are honest)

1. Stratified 80/20 split, fixed seed.
2. 5-fold cross-validation **on the 80% only** to choose between Logistic Regression,
   Random Forest and Histogram Gradient Boosting (metric: F1).
3. The winner is evaluated **once** on the untouched 20%: these are the reported metrics.
4. The saved model is then refit on 100% of the data for the app.

The test set is never used to pick a model, so the reported score is not inflated by selection.

## Design decisions

- **Lexical features only.** No DNS, WHOIS, page download or screenshots. Benefits: free,
  millisecond latency, works offline, and a dangerous page is never contacted.
  Cost: the model cannot see page content, domain age or certificates.
- **Explanations are separate from the verdict.** The model decides; `explain.py` only lists
  human-readable reasons. They can disagree in rare cases, which is a good topic for your report.
- **No `tldextract`.** A small built-in list of two-part suffixes (`co.uk`, ...) keeps the
  dependency list minimal. Swap in `tldextract` for production-grade accuracy.
- **Model artifact is one file** (`joblib` dict with the model, metrics, source and date).
