"""Persistent task queue (database-backed).

Why not Redis/Celery: MAKKADi primarily runs as a single-user desktop
application; a DB-backed queue gives persistence, visibility in the UI and
crash recovery without extra infrastructure. The interface is small enough to
be swapped for a distributed queue in a multi-node deployment.

Semantics: at-least-once. On startup, tasks left ``running`` by an interrupted
process are put back to ``pending`` (recovery). Failures are retried with
exponential backoff until ``max_attempts``, then marked ``dead``.
"""

from __future__ import annotations

import asyncio
import traceback
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.errors import ConnectorError, RateLimited
from app.core.logging import get_logger
from app.core.timeutil import utc_now
from app.models import Task

log = get_logger("makkadi.tasks")
Handler = Callable[[Session, dict[str, Any]], Awaitable[dict[str, Any] | None]]
HANDLERS: dict[str, Handler] = {}
BACKOFF_BASE_SECONDS = 5
BACKOFF_MAX_SECONDS = 900


def handler(name: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        HANDLERS[name] = fn
        return fn
    return deco


def enqueue(db: Session, type_: str, payload: dict[str, Any], *, dedup_key: str | None = None,
            max_attempts: int = 5, delay_seconds: float = 0) -> Task:
    if dedup_key:
        existing = db.scalars(select(Task).where(Task.dedup_key == dedup_key, Task.status == "pending")).first()
        if existing:
            return existing
    task = Task(type=type_, payload=payload, dedup_key=dedup_key, max_attempts=max_attempts,
                next_run_at=utc_now() + timedelta(seconds=delay_seconds))
    db.add(task)
    db.flush()
    return task


def recover_interrupted(db: Session) -> int:
    result = db.execute(
        update(Task).where(Task.status == "running")
        .values(status="pending", locked_at=None, last_error="Reprise après interruption du traitement")
    )
    db.commit()
    return result.rowcount or 0


def _claim(db: Session) -> Task | None:
    now = utc_now()
    task = db.scalars(
        select(Task).where(Task.status == "pending", Task.next_run_at <= now).order_by(Task.next_run_at, Task.id).limit(1)
    ).first()
    if task is None:
        return None
    claimed = db.execute(
        update(Task).where(Task.id == task.id, Task.status == "pending")
        .values(status="running", locked_at=now, attempts=Task.attempts + 1)
    )
    db.commit()
    if not claimed.rowcount:
        return None
    db.refresh(task)
    return task


async def run_one(session_factory: Callable[[], Session]) -> bool:
    """Claim and execute one due task. Returns False when the queue is idle."""
    with session_factory() as db:
        task = _claim(db)
        if task is None:
            return False
        fn = HANDLERS.get(task.type)
        try:
            if fn is None:
                raise ConnectorError(f"Type de tâche inconnu : {task.type}")
            result = await fn(db, dict(task.payload))
            db.commit()
            task.status, task.result, task.last_error, task.finished_at = "succeeded", result, None, utc_now()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            retryable = not isinstance(exc, ConnectorError) or exc.retryable
            message = str(exc) if isinstance(exc, ConnectorError) else f"{type(exc).__name__}: {exc}"
            if not isinstance(exc, ConnectorError):
                log.error("task failed", extra={"ctx": {"task": task.id, "trace": traceback.format_exc()[-2000:]}})
            task = db.get(Task, task.id)
            task.last_error = message[:2000]
            if retryable and task.attempts < task.max_attempts:
                delay = exc.retry_after if isinstance(exc, RateLimited) and exc.retry_after else min(
                    BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * 2 ** (task.attempts - 1))
                task.status, task.next_run_at = "pending", utc_now() + timedelta(seconds=delay)
            else:
                task.status, task.finished_at = ("dead" if retryable else "failed"), utc_now()
        task.locked_at = None
        db.commit()
        return True


async def drain(session_factory: Callable[[], Session], max_tasks: int = 1000) -> int:
    """Run due tasks until the queue is idle (tests, CLI)."""
    n = 0
    while n < max_tasks and await run_one(session_factory):
        n += 1
    return n


async def worker_loop(session_factory: Callable[[], Session], poll_seconds: float, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            busy = await run_one(session_factory)
        except Exception:  # noqa: BLE001
            log.exception("worker loop error")
            busy = False
        if not busy:
            try:
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
            except TimeoutError:
                pass
