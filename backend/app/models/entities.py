"""SQLAlchemy data model.

Design notes
------------
* Every timestamp is stored in UTC (``UTCDateTime``).
* API secrets are *never* stored in clear text: ``ConnectorConfig.secret_ciphertext``
  holds a Fernet token encrypted with the master key, which lives outside the DB.
* ``is_synthetic`` flags demo data everywhere it can appear, so the UI and the
  reports can label it "DONNÉE DE DÉMONSTRATION".
* ``AuditLog`` rows are hash-chained (tamper-evident, not tamper-proof).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.timeutil import utc_now
from app.database.base import Base, UTCDateTime


def _uuid() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- users


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    role: Mapped[Role] = relationship(lazy="joined")


# --------------------------------------------------------------------------- connectors


class ConnectorConfig(Base):
    __tablename__ = "connector_configs"
    __table_args__ = (CheckConstraint("kind IN ('siem','osint','ai')", name="kind"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(100), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    last_status: Mapped[str] = mapped_column(String(32), default="never_run")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)


class IngestionCheckpoint(Base):
    """Collection cursor per SIEM connector; only advanced after events are persisted."""

    __tablename__ = "ingestion_checkpoints"

    connector_id: Mapped[int] = mapped_column(
        ForeignKey("connector_configs.id", ondelete="CASCADE"), primary_key=True
    )
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)


# --------------------------------------------------------------------------- events & investigations


class SiemEvent(Base):
    __tablename__ = "siem_events"
    __table_args__ = (
        UniqueConstraint("source_system", "original_id", name="source_original"),
        Index("ix_siem_events_event_time", "event_time"),
        Index("ix_siem_events_src_ip", "src_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connector_id: Mapped[int | None] = mapped_column(
        ForeignKey("connector_configs.id", ondelete="SET NULL"), nullable=True
    )
    source_system: Mapped[str] = mapped_column(String(64))
    original_id: Mapped[str] = mapped_column(String(255))
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    ingest_method: Mapped[str] = mapped_column(String(16))  # poll|webhook|file|demo|manual
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    event_time: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    title: Mapped[str] = mapped_column(String(500), default="")
    event_type: Mapped[str] = mapped_column(String(128), default="unknown")
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    severity_raw: Mapped[str | None] = mapped_column(String(64), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attempt_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_sha256: Mapped[str] = mapped_column(String(64))
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (Index("ix_investigations_created_at", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    reference: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    severity: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    source_system: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    restricted: Mapped[bool] = mapped_column(Boolean, default=False)
    pipeline_status: Mapped[str] = mapped_column(String(32), default="pending")
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence_level: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    scoring: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    correlation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    owner: Mapped[User | None] = relationship(lazy="joined")
    events: Mapped[list[SiemEvent]] = relationship(secondary="investigation_events", lazy="selectin")
    assignees: Mapped[list[User]] = relationship(secondary="investigation_assignees", lazy="selectin")


class InvestigationEvent(Base):
    __tablename__ = "investigation_events"

    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(ForeignKey("siem_events.id", ondelete="CASCADE"), primary_key=True)


class InvestigationAssignee(Base):
    __tablename__ = "investigation_assignees"

    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("type", "value", name="type_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    scope: Mapped[str] = mapped_column(String(32), default="public")  # public|private|reserved|...
    classification: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)


class InvestigationIndicator(Base):
    __tablename__ = "investigation_indicators"

    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), primary_key=True)  # source|destination|observed
    extracted_from: Mapped[str] = mapped_column(String(128), default="")
    event_id: Mapped[int | None] = mapped_column(ForeignKey("siem_events.id", ondelete="SET NULL"), nullable=True)

    indicator: Mapped[Indicator] = relationship(lazy="joined")


# --------------------------------------------------------------------------- OSINT


class OsintSource(Base):
    """Registry of OSINT/TI sources with their reliability and upstream group."""

    __tablename__ = "osint_sources"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32))
    upstream_group: Mapped[str] = mapped_column(String(64))
    reliability: Mapped[float] = mapped_column(Float, default=0.6)
    requires_api_key: Mapped[bool] = mapped_column(Boolean, default=False)
    terms_url: Mapped[str | None] = mapped_column(String(512), nullable=True)


class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"
    __table_args__ = (Index("ix_enrichment_inv_ind", "investigation_id", "indicator_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"))
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    source_name: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32))  # ok|no_data|error|not_configured|rate_limited|skipped|unsupported
    queried_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    data_updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    findings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw: Mapped[Any] = mapped_column(JSON, nullable=True)
    raw_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reference_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    source_confidence: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)

    indicator: Mapped[Indicator] = relationship(lazy="joined")


class IndicatorRelation(Base):
    """Qualified link between two nodes (indicator, ASN, organisation, certificate, event...).

    A relation is an observation reported by a source; it is never a proof of causality.
    """

    __tablename__ = "indicator_relations"
    __table_args__ = (Index("ix_relations_investigation", "investigation_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"))
    from_kind: Mapped[str] = mapped_column(String(32))
    from_value: Mapped[str] = mapped_column(String(2048))
    to_kind: Mapped[str] = mapped_column(String(32))
    to_value: Mapped[str] = mapped_column(String(2048))
    relation_type: Mapped[str] = mapped_column(String(64))
    source_name: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    temporality: Mapped[str] = mapped_column(String(16), default="unknown")  # current|historical|unknown
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    evidence_result_id: Mapped[int | None] = mapped_column(
        ForeignKey("enrichment_results.id", ondelete="SET NULL"), nullable=True
    )
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


# --------------------------------------------------------------------------- AI & reports


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32))  # ok|rejected|error|disabled
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    output: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    validation_issues: Mapped[list[str]] = mapped_column(JSON, default=list)
    injection_flags: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    input_sha256: Mapped[str] = mapped_column(String(64))
    data_sent_externally: Mapped[bool] = mapped_column(Boolean, default=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # technical|executive
    format: Mapped[str] = mapped_column(String(8))  # pdf|json
    file_name: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class InvestigationNote(Base):
    """Analyst notes and decisions (status changes, verdicts)."""

    __tablename__ = "investigation_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    kind: Mapped[str] = mapped_column(String(16))  # note|decision|status
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)

    user: Mapped[User | None] = relationship(lazy="joined")


# --------------------------------------------------------------------------- operations


class Task(Base):
    __tablename__ = "tasks"
    __table_args__ = (Index("ix_tasks_status_next", "status", "next_run_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|running|succeeded|failed|dead
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    dedup_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    next_run_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    locked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_target", "target_type", "target_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, onupdate=utc_now)
