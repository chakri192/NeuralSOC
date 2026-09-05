"""Test-only environment defaults, applied before any test module imports
api.main / api.deps (which read these at import time and raise if missing).
setdefault() so a real CI/dev environment can still override any of these.
"""
import os

os.environ.setdefault("TSOC_API_KEY", "test-only-static-key-do-not-use-in-prod")
os.environ.setdefault("TSOC_JWT_SECRET", "test-only-jwt-secret-do-not-use-in-prod")
os.environ.setdefault("DATABASE_URL", "sqlite:///./_test_api.db")
os.environ.setdefault("REDIS_SSL", "false")
os.environ.setdefault("REDIS_PASSWORD", "test-only-redis-password-do-not-use-in-prod")
os.environ.setdefault("ENABLE_DOCS", "false")

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _cleanup_test_db():
    yield
    db_path = "./_test_api.db"
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture(scope="session", autouse=True)
def _fake_redis_for_module_level_construction():
    """inference/stream_processor_faust.py constructs a real
    IncidentCorrelator() at MODULE IMPORT TIME (not lazily), so merely
    importing that module -- even to test an unrelated helper function --
    would otherwise require a live, reachable Redis for the whole test
    session. Patch the same construction points tests/test_pipeline.py's
    _make_correlator() patches per-test, but at session scope, so any such
    module-level construction gets a working fake instead of crashing the
    import. Individual tests that need their OWN isolated correlator still
    get one via _make_correlator()'s per-test patch, which takes
    precedence while active."""
    import fakeredis
    from unittest.mock import patch

    from inference.correlation import IncidentCorrelator

    fake = fakeredis.FakeStrictRedis(decode_responses=True)
    redis_patcher = patch("inference.correlation.redis.Redis", return_value=fake)
    master_patcher = patch.object(IncidentCorrelator, "check_redis_master", return_value=True)
    redis_patcher.start()
    master_patcher.start()
    yield
    master_patcher.stop()
    redis_patcher.stop()
