# HTTP API

Base URL (local): `http://127.0.0.1:5000`

## `POST /api/analyze`

Request:
```json
{ "url": "http://paypal.secure-login-update.xyz/signin.php" }
```

Response `200`:
```json
{
  "url": "http://paypal.secure-login-update.xyz/signin.php",
  "verdict": "phishing",
  "probability_phishing": 0.9667,
  "confidence": 0.9667,
  "risk_level": "high",
  "red_flags": [
    {"code": "brand_misuse", "message": "A well-known brand name appears in ...", "severity": 3, "part": "subdomain"}
  ],
  "parts": {"scheme": "http", "subdomain": "paypal", "domain": "secure-login-update", "suffix": "xyz", "path": "/signin.php", "query": ""},
  "features": {"url_length": 49, "...": "..."}
}
```

- `verdict`: `phishing` if `probability_phishing >= 0.5`, otherwise `legitimate`.
- `risk_level`: `low` (< 0.35), `medium` (< 0.65), `high` (>= 0.65). Thresholds live in `config.py`.
- Errors return `400` with `{"error": "..."}`.

## `GET /api/model`
Model name, test metrics, cross-validation scores, data source, training date.

## `GET /api/health`
`{"status": "ok"}`

## Example with curl

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"url":"https://github.com"}'
```
