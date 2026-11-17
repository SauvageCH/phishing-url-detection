# Feature reference

All features are computed in `src/feature_extraction.py::extract_features`.
A URL is first split into `scheme://subdomain.domain.suffix:port/path?query`.

| Group | Features | Why it helps |
|-------|----------|--------------|
| Size | `url_length`, `host_length`, `path_length`, `query_length`, `domain_length` | Phishing URLs are often long to hide the real host. |
| Characters | `count_dots`, `count_hyphens_host`, `count_hyphens_url`, `count_underscores`, `count_at`, `count_question`, `count_equals`, `count_ampersand`, `count_percent`, `count_slashes`, `count_digits`, `digit_ratio`, `special_char_ratio` | Unusual punctuation and digits are typical of generated URLs. |
| Host | `has_ip_host`, `has_port`, `subdomain_count`, `domain_has_digits`, `domain_has_hyphen`, `longest_host_token`, `has_punycode`, `has_userinfo` | Raw IPs, deep subdomain chains, `@` tricks and `xn--` look-alikes. |
| Protocol | `is_https` | Weak signal alone (many phishing sites use HTTPS) but useful in combination. |
| Reputation lists | `is_suspicious_tld`, `is_shortener` | Cheap TLDs (`.xyz`, `.top`, `.tk`) and shorteners are over-represented in phishing. |
| Language | `keyword_count`, `keyword_in_host` | Words such as `login`, `verify`, `secure`, `update`. |
| Randomness | `host_entropy`, `url_entropy` | Shannon entropy: random strings score higher than words. |
| Brands | `brand_in_subdomain_or_path`, `brand_in_domain_not_exact`, `is_typosquat` | `paypal.evil.xyz`, `paypal-secure.com`, `paypa1.com`. |
| Path | `path_depth`, `double_slash_in_path`, `has_hex_encoding`, `file_extension_suspicious` | Redirect tricks, encoded payloads, `.php`/`.exe` targets. |

## Adding a feature

1. Compute it inside `extract_features` and return it in the dict.
2. Add its name to `FEATURE_NAMES` (the order is the model's column order).
3. Retrain: `python -m src.train`. Old model files must be retrained because the columns changed.
4. Optionally add a human message in `src/explain.py` and a test in `tests/`.

Ideas for extensions: URL age via WHOIS (needs network), Google Safe Browsing lookup (free API key),
character n-gram TF-IDF with a linear model, a small character-level neural network.
