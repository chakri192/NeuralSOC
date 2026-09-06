"""api/deps.py's rate-limiter Redis TLS URI construction had no direct
unit coverage -- only ever exercised indirectly through the module's own
import-time side effects. _build_redis_storage_uri() is a pure function
pulled out specifically so this is testable without reimporting a module
that constructs a real Limiter as a side effect.
"""
from api.deps import _build_redis_storage_uri


def test_plaintext_uri_has_no_ssl_params():
    uri = _build_redis_storage_uri("redis", "localhost", "6379", "pw", False, None, None, None)
    assert uri == "redis://:pw@localhost:6379/1"


def test_ssl_with_no_ca_or_client_cert_has_no_query_string():
    uri = _build_redis_storage_uri("rediss", "localhost", "6379", "pw", True, None, None, None)
    assert uri == "rediss://:pw@localhost:6379/1"


def test_ssl_with_ca_cert_only(tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_text("fake")
    uri = _build_redis_storage_uri("rediss", "localhost", "6379", "pw", True, str(ca), None, None)
    assert f"ssl_ca_certs={ca}" in uri
    assert "ssl_certfile" not in uri


def test_ssl_with_nonexistent_ca_cert_path_is_ignored():
    uri = _build_redis_storage_uri("rediss", "localhost", "6379", "pw", True, "/no/such/file", None, None)
    assert "ssl_ca_certs" not in uri


def test_ssl_with_client_cert_and_key(tmp_path):
    cert, key = tmp_path / "client.crt", tmp_path / "client.key"
    cert.write_text("fake-cert")
    key.write_text("fake-key")
    uri = _build_redis_storage_uri("rediss", "localhost", "6379", "pw", True, None, str(cert), str(key))
    assert f"ssl_certfile={cert}" in uri
    assert f"ssl_keyfile={key}" in uri


def test_ssl_with_only_client_cert_no_key_is_not_applied(tmp_path):
    cert = tmp_path / "client.crt"
    cert.write_text("fake-cert")
    uri = _build_redis_storage_uri("rediss", "localhost", "6379", "pw", True, None, str(cert), None)
    assert "ssl_certfile" not in uri
    assert "ssl_keyfile" not in uri


def test_ssl_with_client_cert_path_set_but_file_missing_is_not_applied(tmp_path):
    # k8s/soc-deployment.yaml sets REDIS_CLIENT_CERT_PATH/_KEY_PATH
    # unconditionally to a cert-manager Secret's mount path -- if that
    # Certificate was never actually issued (cert-manager not installed,
    # or still pending), the env vars are set but the files aren't real.
    # redis-py would otherwise only discover that by failing to build an
    # SSL context at connection time.
    missing_cert = str(tmp_path / "client.crt")  # never written
    missing_key = str(tmp_path / "client.key")
    uri = _build_redis_storage_uri("rediss", "localhost", "6379", "pw", True, None, missing_cert, missing_key)
    assert "ssl_certfile" not in uri
    assert "ssl_keyfile" not in uri


def test_ssl_with_ca_and_client_cert_together(tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_text("fake")
    cert, key = tmp_path / "client.crt", tmp_path / "client.key"
    cert.write_text("fake-cert")
    key.write_text("fake-key")
    uri = _build_redis_storage_uri("rediss", "localhost", "6379", "pw", True, str(ca), str(cert), str(key))
    assert f"ssl_ca_certs={ca}" in uri
    assert f"ssl_certfile={cert}" in uri
    assert f"ssl_keyfile={key}" in uri
    # Exactly one '?' -- both sets of params joined into one query string, not two.
    assert uri.count("?") == 1


def test_no_password_omits_auth_segment():
    uri = _build_redis_storage_uri("redis", "localhost", "6379", None, False, None, None, None)
    assert uri == "redis://localhost:6379/1"
