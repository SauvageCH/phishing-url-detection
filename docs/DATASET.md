# Datasets

The training code accepts any CSV with two columns:

```csv
url,label
https://www.wikipedia.org/,0
http://paypal.verify-login.xyz/signin.php,1
```

`label` can be `0/1` or words such as `legitimate/phishing`, `benign/malicious`, `good/bad`.
Put your file at **`data/raw/dataset.csv`** and `python -m src.train` will use it automatically.

## Option 1: synthetic data (default, zero setup)

`src/generate_dataset.py` fabricates 8,000 balanced URLs from the patterns described in the
phishing literature (brand in subdomain, typosquatting, IP hosts, `@` trick, free hosting,
compromised sites, punycode...) with 2 % label noise.

**Limitation:** the generator and the feature extractor were written by the same person, so
the model partly learns the author's own rules. Scores around 98 % are encouraging for the
pipeline, **not** a measure of real-world performance.

## Option 2: free real data

| Source | Content | Cost / account |
|--------|---------|----------------|
| [OpenPhish feed](https://openphish.com/feed.txt) | ~hundreds of live phishing URLs, refreshed often | Free, no account |
| [Tranco list](https://tranco-list.eu/) | Top 1 M legitimate domains (research-grade ranking) | Free, no account |
| [PhishTank](https://phishtank.org/developer_info.php) | Large verified phishing archive | Free, API key needed |
| [UCI "Phishing Websites"](https://archive.ics.uci.edu/) | Pre-computed features (not raw URLs) | Free |
| Kaggle "Phishing Site URLs" / "Malicious URLs" | Raw labelled URLs | Free account |

One command builds a dataset from the first two:

```bash
python -m src.download_data --max-per-class 5000
python -m src.train
```

## Known biases to mention in your report

- **Path bias:** Tranco only lists domains, while phishing feeds contain full URLs. Without care
  the model learns "has a path => phishing". `download_data.py` attaches plausible paths to
  legitimate domains to reduce this, which is itself an approximation.
- **Time drift:** phishing tactics change within weeks. A model should be retrained regularly.
- **Class balance:** real traffic is mostly legitimate; precision matters more than on a 50/50 set.
