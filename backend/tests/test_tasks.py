import asyncio
from datetime import timedelta

import httpx
from sqlalchemy import func, select

from app.core.errors import ConnectorError
from app.core.timeutil import utc_now
from app.database.session import SessionLocal
from app.investigation.pipeline import poll_connector, schedule_due_polls
from app.models import ConnectorConfig, IngestionCheckpoint, SiemEvent, Task
from app.services import tasks as tq
from tests.conftest import drain

calls = {"n": 0}


@tq.handler("test_flaky")
async def _flaky(db, payload):
    calls["n"] += 1
    if calls["n"] <= payload["fail_times"]:
        raise ConnectorError("panne temporaire", retryable=True)
    return {"ok": True}


@tq.handler("test_fatal")
async def _fatal(db, payload):
    raise ConnectorError("erreur définitive", retryable=False)


def _make_due(db):
    for t in db.scalars(select(Task).where(Task.status == "pending")):
        t.next_run_at = utc_now() - timedelta(seconds=1)
    db.commit()


def test_retry_with_backoff_then_success(db):
    calls["n"] = 0
    t = tq.enqueue(db, "test_flaky", {"fail_times": 2})
    db.commit()
    drain()
    db.refresh(t)
    assert t.status == "pending" and t.attempts == 1 and t.next_run_at > utc_now() and "panne" in t.last_error
    for _ in range(2):
        _make_due(db)
        drain()
    db.refresh(t)
    assert t.status == "succeeded" and t.attempts == 3 and t.result == {"ok": True}


def test_dead_after_max_attempts_and_non_retryable(db):
    calls["n"] = 0
    t = tq.enqueue(db, "test_flaky", {"fail_times": 99}, max_attempts=2)
    f = tq.enqueue(db, "test_fatal", {})
    db.commit()
    for _ in range(3):
        drain()
        _make_due(db)
    db.refresh(t)
    db.refresh(f)
    assert t.status == "dead" and t.attempts == 2
    assert f.status == "failed" and f.attempts == 1


def test_dedup_and_recovery_of_interrupted_tasks(db):
    a = tq.enqueue(db, "test_flaky", {"fail_times": 0}, dedup_key="k1")
    b = tq.enqueue(db, "test_flaky", {"fail_times": 0}, dedup_key="k1")
    assert a.id == b.id
    a.status = "running"  # simulate a crash during execution
    db.commit()
    assert tq.recover_interrupted(db) == 1
    db.refresh(a)
    assert a.status == "pending" and "Reprise" in a.last_error


def test_poll_resumes_from_checkpoint_after_failure(db, mock_http):
    state = {"fail": False, "since": []}

    def handler(req):
        state["since"].append(req.url.params.get("since"))
        if state["fail"]:
            return httpx.Response(500)
        return httpx.Response(200, json=[{"id": "P1", "timestamp": "2026-10-25T22:14:35Z", "src_ip": "154.73.112.25", "severity": "high"}])

    mock_http(handler)
    row = ConnectorConfig(kind="siem", provider="generic_rest", name="poll1", enabled=True,
                          settings={"url": "https://api.example.org/events", "auth_type": "none", "initial_lookback_minutes": 5256000}, poll_interval_seconds=60)
    db.add(row)
    db.commit()
    result = asyncio.run(poll_connector(db, row.id))
    assert result["created"] == 1
    cp = db.get(IngestionCheckpoint, row.id)
    assert cp.cursor == "2026-10-25T22:14:35Z"
    # second run: same event re-delivered (inclusive cursor) -> deduplicated, no new event
    asyncio.run(poll_connector(db, row.id))
    assert db.scalar(select(func.count()).select_from(SiemEvent)) == 1
    # failure: cursor unchanged, status visible
    state["fail"] = True
    try:
        asyncio.run(poll_connector(db, row.id))
    except ConnectorError:
        pass
    db.expire_all()
    assert db.get(IngestionCheckpoint, row.id).cursor == "2026-10-25T22:14:35Z"
    assert db.get(ConnectorConfig, row.id).last_status == "error"
    assert state["since"][-1] == "2026-10-25T22:14:35Z"


def test_scheduler_enqueues_due_polls_once(db):
    db.add(ConnectorConfig(kind="siem", provider="generic_rest", name="sched", enabled=True, settings={}, poll_interval_seconds=60))
    db.commit()
    assert schedule_due_polls(db) == 1
    assert schedule_due_polls(db) == 0  # already pending


def test_retention_purge(client, admin, db):
    from app.models import Investigation
    from app.services.retention import purge

    client.post("/api/v1/ingest/demo", headers=admin)
    drain()
    inv = db.scalars(select(Investigation)).first()
    inv.status = "closed_benign"
    inv.updated_at = utc_now() - timedelta(days=400)
    db.commit()
    with SessionLocal() as s2:
        result = purge(s2)
    assert result["investigations"] == 1
