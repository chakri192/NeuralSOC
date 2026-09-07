from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from api.database import Base

ANALYST = "analyst"
LEAD = "lead"
ADMIN = "admin"
VALID_ROLES = {ANALYST, LEAD, ADMIN}

# Triage status -- same states shared/triage_store.py used when this was
# local SQLite (kept identical so dashboard/terminal display logic that
# already knows these four strings doesn't need to change).
TRIAGE_OPEN = "open"
TRIAGE_ACKNOWLEDGED = "acknowledged"
TRIAGE_FALSE_POSITIVE = "false_positive"
TRIAGE_CONFIRMED = "confirmed"
VALID_TRIAGE_STATUSES = {TRIAGE_OPEN, TRIAGE_ACKNOWLEDGED, TRIAGE_FALSE_POSITIVE, TRIAGE_CONFIRMED}

# Role -> scopes granted at login (api/auth.py's create_token embeds these
# in the issued JWT; api/deps.py's require_scope() enforces them per route).
# Only admin can invite/deactivate teammates -- everyone else is read +
# triage-write on their own tenant's data.
ROLE_SCOPES = {
    ANALYST: ["alerts:read", "stats:read", "triage:write"],
    LEAD: ["alerts:read", "stats:read", "triage:write"],
    ADMIN: ["alerts:read", "stats:read", "triage:write", "users:manage"],
}


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, index=True, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    users = relationship("User", back_populates="tenant")
    alerts = relationship("Alert", back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default=ANALYST)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant", back_populates="users")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    # Nullable for now, deliberately: api/kafka_sink.py (the only writer)
    # doesn't know about tenants yet -- that lands in the ingestion-isolation
    # phase, which also tightens this to nullable=False once every writer
    # is guaranteed to supply a real tenant_id. Until then, NULL means
    # "ingested before tenant isolation existed" rather than a constraint
    # violation that would break the pipeline today.
    tenant_id = Column(Integer, ForeignKey("tenants.id", name="fk_alerts_tenant_id"), nullable=True, index=True)
    alert_id = Column(String, unique=True, index=True, nullable=False)
    timestamp = Column(String, index=True, nullable=False)
    event_type = Column(String, nullable=False)

    # PERFORMANCE FIX: Added index=True to prevent Full Table Scans on dashboard stats
    threat_class = Column(String, index=True)
    confidence_score = Column(Float)
    severity = Column(String, index=True)

    source_ip = Column(String)
    destination_ip = Column(String)
    evidence = Column(Text)  # JSON string representation
    trace_id = Column(String, index=True, nullable=True)

    # Rest of the canonical alert schema (inference/schemas.py ALERT_SCHEMA).
    # These were previously silently dropped by the Kafka sink's field
    # whitelist even though the pipeline always produces them -- that's the
    # real cause of the dashboard's Investigate/Incidents pages crashing on
    # a missing flow_id / model_name, not just a missing default.
    flow_id = Column(String, index=True, nullable=True)
    span_id = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    model_name = Column(String, nullable=True)
    model_version = Column(String, nullable=True)
    schema_version = Column(String, nullable=True)

    tenant = relationship("Tenant", back_populates="alerts")


class IncidentTriage(Base):
    """Replaces shared/triage_store.py's local SQLite table. incident_id
    is a client-synthesized string (f"INC-{source_ip}") -- NOT globally
    unique across tenants, since two different tenants' networks can
    both see traffic from the same IP. The real key is (tenant_id,
    incident_id) together; a bare incident_id primary key (the old
    SQLite table's design) would silently conflate two different
    tenants' incidents that happen to share an IP-derived id."""

    __tablename__ = "incident_triage"
    __table_args__ = (UniqueConstraint("tenant_id", "incident_id", name="uq_incident_triage_tenant_incident"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    incident_id = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default=TRIAGE_OPEN)
    note = Column(Text, nullable=True)
    # Who actually did this -- a verified foreign key now, not a
    # free-text string an analyst typed (or the local OS username) that
    # nothing ever cross-checked against who was actually authenticated.
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    tenant = relationship("Tenant")
    actor = relationship("User")


class SensorToken(Base):
    """A per-tenant credential for the ingestion boundary: each tenant's
    on-prem collector (api/kafka_sink.py's ingest client, going forward)
    authenticates with one of these against POST /api/v1/ingest/alerts,
    so a compromised sensor at Tenant A can never write data tagged as
    Tenant B. Only the SHA-256 hash is stored -- the cleartext token is
    shown once at creation time (see api/routes/ingest.py's
    create_sensor_token) and is not retrievable again, the same
    convention as GitHub/AWS API keys."""

    __tablename__ = "sensor_tokens"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant")
