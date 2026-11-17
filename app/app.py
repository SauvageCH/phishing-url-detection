"""
Flask web application.

Routes
  GET  /            the web page
  POST /api/analyze  {"url": "..."} -> full analysis (JSON)
  GET  /api/model    metrics of the loaded model
  GET  /api/health   liveness check

The app never opens the URL it analyses: it only reads the text.
"""
from __future__ import annotations

from flask import Flask, jsonify, render_template, request

import config
from src.predict import ModelNotFoundError, PhishingDetector

EXAMPLES = [
    "https://github.com/python/cpython",
    "https://www.wikipedia.org",
    "http://paypal.secure-login-update.xyz/signin.php",
    "http://192.168.10.5:8080/paypal/verify.php",
    "https://paypa1-support.com/account/confirm",
    "http://google.com@free-prizes.top/claim",
]


def create_app(model_path=config.MODEL_PATH) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # reject huge request bodies

    try:
        detector = PhishingDetector(model_path)
    except ModelNotFoundError as exc:
        raise SystemExit(str(exc))

    @app.get("/")
    def index():
        return render_template("index.html", examples=EXAMPLES, model=detector.info)

    @app.post("/api/analyze")
    def analyze():
        payload = request.get_json(silent=True) or {}
        url = payload.get("url", "")
        if not isinstance(url, str):
            return jsonify(error="'url' must be a string."), 400
        try:
            return jsonify(detector.analyze(url))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @app.get("/api/model")
    def model_info():
        return jsonify(detector.info)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    return app
