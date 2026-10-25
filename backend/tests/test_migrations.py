from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from app.database.base import Base
from app.database.migrate import alembic_config


def test_upgrade_matches_models_and_downgrade(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "head")
    engine = create_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": False}), Base.metadata)
    assert diff == [], diff
    tables = set(inspect(engine).get_table_names())
    assert {"investigations", "siem_events", "indicators", "enrichment_results", "audit_logs", "tasks",
            "connector_configs", "ai_analyses", "reports", "users", "roles"} <= tables
    command.downgrade(cfg, "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    command.upgrade(cfg, "head")  # idempotent re-upgrade


def test_unique_constraint_on_siem_events(tmp_path):
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    from app.models import SiemEvent

    url = f"sqlite:///{tmp_path / 'u.db'}"
    command.upgrade(alembic_config(url), "head")
    engine = create_engine(url)
    with Session(engine) as s:
        for _ in range(2):
            s.add(SiemEvent(source_system="s", original_id="1", content_hash="h", ingest_method="file", raw_sha256="x"))
        try:
            s.commit()
            raise AssertionError("duplicate accepted")
        except IntegrityError:
            s.rollback()
