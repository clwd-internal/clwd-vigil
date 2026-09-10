"""Container readiness probe.

``/api/health`` answers 200 unconditionally — the except branch returns
``{"status": "healthy"}`` too. As a liveness probe that is arguably fine: the
process is up and serving. As a *readiness* probe it is useless, and Container
Apps uses readiness to decide whether to route traffic to a replica and whether
a new revision is safe to promote. A replica whose database is unreachable
would be declared ready, take traffic, and fail every request.

Changing ``/api/health`` is not an option: Docker HEALTHCHECKs, the existing
compose stack and anything already pointed at it expect its current behaviour,
and it is a hot upstream file. So this adds a second endpoint next to it,
mounted through the ``ROUTER_META`` discovery seam, with no edit to
``services/api/main.py`` other than the one line that marks the path public.

The contract:

    200  everything a request needs is reachable
    503  a hard dependency is not

Postgres is a hard dependency: without it there is nothing to serve. Redis is
conditionally hard — it backs the token blacklist and ingestion dedup, so a
replica without it will silently double-ingest and fail to honour logouts.
``VIGIL_READINESS_REQUIRE_REDIS`` (default true when a redis_url is configured)
decides, because a single-node local run legitimately has no Redis.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict

from fastapi import APIRouter, Response

from core.routing import Auth, RouterMeta

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/health/ready",
    tags=["health"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "Container Apps readiness probes are issued by the platform, which "
        "holds no session cookie and cannot obtain one. The handler returns "
        "component reachability booleans and no configuration, credentials or "
        "hostnames, so there is nothing here to authenticate access to."
    ),
)

#: A probe that hangs is worse than one that fails: Container Apps counts a
#: timeout as a failure anyway, but a hung handler holds a worker thread.
_TIMEOUT_SECONDS = 5.0


def _require_redis() -> bool:
    raw = (os.environ.get("VIGIL_READINESS_REQUIRE_REDIS") or "").strip().lower()
    if raw in ("1", "true", "yes"):
        return True
    if raw in ("0", "false", "no"):
        return False
    # Unset: required only if the deployment actually configured a Redis.
    try:
        from core.config import get_settings

        return bool(get_settings().redis_url)
    except Exception:
        return False


def _check_database() -> Dict[str, Any]:
    try:
        from core.storage.connection import get_db_manager

        return {"ok": bool(get_db_manager().health_check())}
    except Exception as e:
        # The message names the failure class, not the connection string: this
        # route is public and a DSN in a probe response is a credential leak.
        return {"ok": False, "error": type(e).__name__}


async def _check_redis() -> Dict[str, Any]:
    try:
        from core.redis_client import get_async_redis

        client = get_async_redis("readiness probe")
        if client is None:
            return {"ok": False, "error": "redis driver unavailable"}
        await client.ping()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}


@router.get("")
async def readiness(response: Response) -> Dict[str, Any]:
    checks: Dict[str, Any] = {}

    try:
        checks["database"] = await asyncio.wait_for(
            asyncio.to_thread(_check_database), timeout=_TIMEOUT_SECONDS
        )
    except Exception as e:
        checks["database"] = {"ok": False, "error": type(e).__name__}

    redis_required = _require_redis()
    if redis_required:
        try:
            checks["redis"] = await asyncio.wait_for(
                _check_redis(), timeout=_TIMEOUT_SECONDS
            )
        except Exception as e:
            checks["redis"] = {"ok": False, "error": type(e).__name__}
    else:
        checks["redis"] = {"ok": True, "skipped": "not required by configuration"}

    ready = all(bool(c.get("ok")) for c in checks.values())
    if not ready:
        response.status_code = 503
        logger.warning(
            "readiness probe failed: %s",
            {k: v for k, v in checks.items() if not v.get("ok")},
        )

    return {"ready": ready, "checks": checks}
