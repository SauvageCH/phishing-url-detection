import pytest

from src.generate_dataset import generate_dataset
from src.predict import PhishingDetector
from src.train import train


@pytest.fixture(scope="module")
def detector(tmp_path_factory):
    out = tmp_path_factory.mktemp("model")
    df = generate_dataset(2000, seed=1)
    train(df, models_dir=out, reports_dir=out, source="test", verbose=False)
    return PhishingDetector(out / "model.joblib")


def test_dataset_is_balanced_and_unique():
    df = generate_dataset(1000, seed=3)
    assert df.url.is_unique
    assert 0.45 < df.label.mean() < 0.55


def test_obvious_cases(detector):
    assert detector.analyze("https://www.wikipedia.org/wiki/Python")["verdict"] == "legitimate"
    assert detector.analyze("http://paypal.secure-login-update.xyz/signin.php")["verdict"] == "phishing"


def test_output_schema(detector):
    r = detector.analyze("http://192.168.1.5/paypal/login.php")
    for key in ("verdict", "probability_phishing", "risk_level", "red_flags", "parts"):
        assert key in r
    assert 0 <= r["probability_phishing"] <= 1


def test_invalid_input(detector):
    with pytest.raises(ValueError):
        detector.analyze("")
    with pytest.raises(ValueError):
        detector.analyze("a" * 5000)


def test_flask_api(detector):
    from app.app import create_app
    client = create_app(detector._path).test_client()
    assert client.get("/api/health").json["status"] == "ok"
    ok = client.post("/api/analyze", json={"url": "https://github.com"})
    assert ok.status_code == 200
    assert client.post("/api/analyze", json={"url": ""}).status_code == 400
    assert client.get("/").status_code == 200
