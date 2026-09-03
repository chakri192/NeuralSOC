from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

# Fallback to SQLite if PostgreSQL is not configured, but default to Postgres for the new architecture
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "")
if not SQLALCHEMY_DATABASE_URL:
    raise RuntimeError("CRITICAL ERROR: DATABASE_URL environment variable is missing. Halting boot sequence.")

# Connect args specific to SQLite vs Postgres
connect_args = {"connect_timeout": 5}


engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=5, pool_recycle=3600, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
