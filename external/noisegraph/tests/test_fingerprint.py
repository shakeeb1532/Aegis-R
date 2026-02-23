from noisegraph.normalize.fingerprint import fingerprint

def test_fingerprint_stable():
    a = fingerprint("X *", {"source":"h1"}, "log")
    b = fingerprint("X *", {"source":"h1"}, "log")
    assert a == b
