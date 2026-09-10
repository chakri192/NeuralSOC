from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
import os

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "")
if not SQLALCHEMY_DATABASE_URL:
    raise RuntimeError("CRITICAL ERROR: DATABASE_URL environment variable is missing. Halting boot sequence.")

# Connect args and pool args specific to SQLite vs Postgres
connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
    "pool_recycle": 1800,
}

if "postgresql" in SQLALCHEMY_DATABASE_URL:
    connect_args["connect_timeout"] = 5
    _db_sslmode = os.getenv("DB_SSLMODE", "verify-full")
    # The default is secure, but nothing previously stopped DB_SSLMODE from
    # being explicitly set to "disable"/"allow"/"prefer" -- all of which
    # either skip encryption entirely or silently downgrade to plaintext if
    # the server doesn't offer TLS. Fail closed on a weak value instead of
    # letting a misconfiguration connect unencrypted or unverified.
    if _db_sslmode not in ("require", "verify-ca", "verify-full"):
        raise RuntimeError(
            f"DB_SSLMODE={_db_sslmode!r} is not acceptable for a Postgres "
            "connection -- must be one of: require, verify-ca, verify-full."
        )
    connect_args["sslmode"] = _db_sslmode
    engine_kwargs.update({
        "pool_size": 20,
        "max_overflow": 20,
        "pool_timeout": 5,
    })
elif "sqlite" in SQLALCHEMY_DATABASE_URL:
    connect_args["timeout"] = 5
    connect_args["check_same_thread"] = False

engine_kwargs["connect_args"] = connect_args

# Sized pool with strict timeout to prevent threadpool starvation
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    **engine_kwargs
)

if "sqlite" in SQLALCHEMY_DATABASE_URL:
    # SQLite's default rollback-journal mode takes an exclusive lock on
    # the whole file for the duration of any write, blocking every other
    # connection's reads until it releases (up to connect_args["timeout"]
    # above) -- with two or more long-lived clients polling the same
    # file (e.g. the web dashboard and terminal/tsoc_console.py each
    # running as their own process), one client's write visibly stalls
    # every other client for seconds at a time. WAL mode lets readers
    # proceed concurrently with a writer; only writer-vs-writer still
    # serializes. Only reachable via the sqlite branch above, which
    # nothing outside local dev/demo ever sets DATABASE_URL to -- real
    # deployments use Postgres (see the postgresql branch), which has
    # proper MVCC and never needed this.
    @event.listens_for(engine, "connect")
    def _enable_sqlite_wal(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA journal_mode=WAL")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# MIGRATION: index for cursor pagination
# execute via alembic or sqlalchemy event: Index('ix_alert_id_desc', Alert.id.desc()).create(bind=engine)
