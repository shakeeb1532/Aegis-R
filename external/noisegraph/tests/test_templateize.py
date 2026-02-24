from noisegraph.normalize.templates import templateize

def test_template_masks_numbers():
    t, _ = templateize("Healthcheck OK latency_ms=123")
    assert "*" in t

def test_template_masks_ip():
    t, f = templateize("Failed password for admin from 1.2.3.4 port 2222 ssh2")
    assert "*" in t
    assert "ip_candidates" in f
