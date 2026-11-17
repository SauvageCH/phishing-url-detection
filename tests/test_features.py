from src.feature_extraction import FEATURE_NAMES, detect_typosquat, extract_features, features_to_frame, parse_url


def test_feature_vector_has_all_columns():
    f = extract_features("https://www.example.com/a?b=1")
    assert list(f.keys()) == FEATURE_NAMES


def test_ip_host_and_port():
    f = extract_features("http://192.168.1.10:8080/login.php")
    assert f["has_ip_host"] == 1 and f["has_port"] == 1 and f["is_https"] == 0


def test_at_symbol_detected():
    assert extract_features("http://google.com@evil.tk/x")["has_userinfo"] == 1


def test_typosquat():
    assert detect_typosquat("paypa1") == "paypal"
    assert detect_typosquat("paypal") is None
    assert detect_typosquat("wikipedia") is None


def test_parse_handles_multi_part_suffix_and_missing_scheme():
    p = parse_url("shop.example.co.uk/path")
    assert (p["subdomain"], p["domain"], p["suffix"]) == ("shop", "example", "co.uk")
    assert p["scheme"] == "https"


def test_garbage_does_not_crash():
    for bad in ["", "http://[::1", "%%%", "   ", "http://"]:
        extract_features(bad)


def test_frame_shape():
    df = features_to_frame(["https://a.com", "http://b.tk/login"])
    assert df.shape == (2, len(FEATURE_NAMES))
