"""The readiness probe, and why /api/health could not be it.

``/api/health`` answers 200 in both its try and its except branch. Container
Apps uses readiness to decide whether to route traffic to a replica and whether
a new revision is safe to promote, so a probe that cannot say "no" means a
replica with an unreachable database is declared ready, takes traffic, and
fails every request it receives.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import Response  # noqa: E402

from core.platform import readiness_router as readiness  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def no_redis_requirement(monkeypatch):
    monkeypatch.setenv("VIGIL_READINESS_REQUIRE_REDIS", "false")


async def _probe():
    response = Response()
    body = await readiness.readiness(response)
    return response.status_code, body


async def test_ready_when_the_database_answers(monkeypatch):
    monkeypatch.setattr(readiness, "_check_database", lambda: {"ok": True})
    status, body = await _probe()
    assert status == 200
    assert body["ready"] is True


async def test_not_ready_when_postgres_is_unreachable(monkeypatch):
    """The whole point. /api/health would answer 200 here."""
    monkeypatch.setattr(
        readiness, "_check_database", lambda: {"ok": False, "error": "OperationalError"}
    )
    status, body = await _probe()
    assert status == 503
    assert body["ready"] is False
    assert body["checks"]["database"]["ok"] is False


async def test_not_ready_when_the_database_check_raises(monkeypatch):
    def boom():
        raise RuntimeError("no pool")

    monkeypatch.setattr(readiness, "_check_database", boom)
    status, body = await _probe()
    assert status == 503


async def test_not_ready_when_redis_is_required_and_unreachable(monkeypatch):
    monkeypatch.setenv("VIGIL_READINESS_REQUIRE_REDIS", "true")
    monkeypatch.setattr(readiness, "_check_database", lambda: {"ok": True})

    async def bad_redis():
        return {"ok": False, "error": "ConnectionError"}

    monkeypatch.setattr(readiness, "_check_redis", bad_redis)
    status, body = await _probe()
    assert status == 503
    assert body["checks"]["redis"]["ok"] is False


async def test_redis_is_skipped_when_not_configured(monkeypatch):
    """A single-node local run legitimately has no Redis; requiring it would
    make the probe unusable outside Azure."""
    monkeypatch.setattr(readiness, "_check_database", lambda: {"ok": True})
    status, body = await _probe()
    assert status == 200
    assert body["checks"]["redis"]["skipped"]


def test_redis_requirement_defaults_to_whether_one_is_configured(monkeypatch):
    monkeypatch.delenv("VIGIL_READINESS_REQUIRE_REDIS", raising=False)

    class _Settings:
        redis_url = "redis://cache:6379/0"

    monkeypatch.setattr("core.config.get_settings", lambda: _Settings())
    assert readiness._require_redis() is True

    _Settings.redis_url = None
    assert readiness._require_redis() is False


async def test_the_probe_body_leaks_no_connection_details(monkeypatch):
    """This route is public. A DSN or a hostname in a probe response is a
    credential leak, so failures report the exception class and nothing else."""
    monkeypatch.setattr(
        readiness,
        "_check_database",
        lambda: (_ for _ in ()).throw(
            RuntimeError("could not connect to postgres://vigil:hunter2@db:5432/vigil")
        ),
    )
    _, body = await _probe()
    rendered = repr(body)
    assert "hunter2" not in rendered
    assert "postgres://" not in rendered
    assert body["checks"]["database"]["error"] == "RuntimeError"


def test_health_ready_is_a_separate_route_from_health():
    """/api/health keeps its always-200 behaviour for the Docker HEALTHCHECKs
    and anything already pointed at it."""
    assert readiness.ROUTER_META.prefix == "/api/health/ready"


def test_the_probe_declares_why_it_is_unauthenticated():
    from core.routing import Auth

    assert readiness.ROUTER_META.auth is not Auth.REQUIRED
    assert "readiness" in readiness.ROUTER_META.reason.lower()
