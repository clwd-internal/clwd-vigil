"""Microsoft Graph security API client for Microsoft Defender XDR.

FORK NOTE (docs/UPSTREAM.md): this file is new in this fork. Upstream's
Defender integration talks to Defender **for Endpoint** at
``api.securitycenter.microsoft.com``, which serves device alerts and device
actions. We need Defender **XDR** — the cross-product correlation layer whose
incidents span endpoint, identity, email and cloud apps — and that lives only
behind Microsoft Graph:

* ``GET  /security/incidents``       — correlated incidents (the SOC's unit of work)
* ``GET  /security/alerts_v2``       — the unified alert schema XDR emits
* ``POST /security/runHuntingQuery`` — advanced hunting (KQL)

Authentication is the client-credentials flow with **no user context**, so the
app registration carries *application* permissions with admin consent:

* ``SecurityIncident.Read.All``  for ``/security/incidents``
* ``SecurityAlert.Read.All``     for ``/security/alerts_v2``
* ``ThreatHunting.Read.All``     for ``/security/runHuntingQuery``

Note that ``alerts_v2`` is not ``alerts``: the legacy ``/security/alerts``
endpoint is the old Graph Security API schema and does not carry XDR's
evidence model. Using it would silently lose the entity data the triage agents
enrich from.

Everything here is instance-agnostic — it takes a credential dict rather than
reading global config — so the same client serves the single-tenant file-config
path and the per-customer Key Vault path in ``core.tenancy``.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

import httpx

logger = logging.getLogger(__name__)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

#: The credential keys every Graph call needs. Shared with the descriptor so
#: the "is it configured" guard and the configurable field set cannot drift.
REQUIRED_FIELDS = ("tenant_id", "client_id", "client_secret")

# Neither upstream call site passed a timeout and requests defaulted to none;
# a hung poll is indistinguishable from a quiet tenant, so all four phases are
# bounded here.
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0)

# Graph pages with @odata.nextLink. Cap the walk so a first run against a busy
# tenant cannot turn into an unbounded fetch; the caller's ``limit`` is the
# real bound and this is the backstop.
_MAX_PAGES = 20


class GraphAuthError(RuntimeError):
    """Token acquisition failed. Distinct from an API error so the caller can
    tell 'these credentials are wrong' from 'Graph returned a 500'."""


class GraphApiError(RuntimeError):
    """A Graph call failed. Carries the status code where we have one."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


# MSAL keeps its own in-memory token cache per application object, so reusing
# the object is what makes token reuse happen. Keyed by (tenant, client_id) —
# never by secret, which would leak rotated secrets into a process-lifetime
# dict.
_APP_CACHE: Dict[tuple, Any] = {}
_APP_CACHE_LOCK = threading.Lock()


def _confidential_app(tenant_id: str, client_id: str, client_secret: str):
    try:
        import msal
    except ImportError as exc:  # pragma: no cover - declared in requirements.txt
        raise GraphAuthError(
            f"msal is required for the Microsoft Defender XDR integration ({exc}). "
            "Install: pip install msal (it is in requirements.txt)."
        ) from exc

    key = (tenant_id, client_id)
    with _APP_CACHE_LOCK:
        app = _APP_CACHE.get(key)
        if app is None:
            app = msal.ConfidentialClientApplication(
                client_id,
                authority=f"https://login.microsoftonline.com/{tenant_id}",
                client_credential=client_secret,
            )
            _APP_CACHE[key] = app
        return app


def reset_token_cache() -> None:
    """Drop every cached MSAL application.

    Called when an instance's credentials are rotated or removed — otherwise a
    revoked secret keeps working until its token expires, and a deleted tenant
    keeps a live token in memory.
    """
    with _APP_CACHE_LOCK:
        _APP_CACHE.clear()


def acquire_token(config: Mapping[str, Any]) -> str:
    """Acquire an application token for Microsoft Graph.

    Blocking. Callers on the event loop must ``asyncio.to_thread`` it.
    """
    missing = [f for f in REQUIRED_FIELDS if not config.get(f)]
    if missing:
        raise GraphAuthError(
            "Microsoft Defender XDR configuration incomplete; missing: "
            + ", ".join(missing)
        )

    app = _confidential_app(
        str(config["tenant_id"]), str(config["client_id"]), str(config["client_secret"])
    )
    result = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
    token = (result or {}).get("access_token")
    if not token:
        # Never log the raw result: on some failures it echoes the client
        # assertion back. error/error_description are safe and are the two
        # fields an operator needs (AADSTS7000215 = bad secret, and so on).
        raise GraphAuthError(
            "Graph token request failed: "
            f"{(result or {}).get('error', 'unknown')}: "
            f"{(result or {}).get('error_description', '')}".strip()
        )
    return token


def _graph_datetime(value: datetime) -> str:
    """Graph's $filter wants a UTC, Z-suffixed, offset-free ISO-8601 stamp.

    ``datetime.isoformat()`` on an aware datetime emits ``+00:00``, and Graph
    rejects the result with a parse error rather than ignoring it. That is
    exactly the bug in upstream's MDE filter, which appends a literal ``Z`` to
    a string that may already carry an offset and produces ``...+00:00Z``.
    """
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.replace(microsecond=0).isoformat() + "Z"


class DefenderXdrClient:
    """Thin synchronous Graph client scoped to the security endpoints.

    Synchronous on purpose: every caller already hops to a worker thread
    (``asyncio.to_thread``), and a sync client keeps the retry/paging logic
    readable. Instantiate per credential set; it is cheap.
    """

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        base_url: str = GRAPH_BASE_URL,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ) -> None:
        self._config = dict(config)
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    # -- plumbing ---------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {acquire_token(self._config)}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get_paged(
        self, path: str, params: Dict[str, Any], limit: int
    ) -> List[Dict[str, Any]]:
        headers = self._headers()
        url = f"{self._base_url}{path}"
        out: List[Dict[str, Any]] = []
        # follow_redirects: Microsoft's endpoints redirect, and httpx (unlike
        # requests) does not follow by default.
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            for _ in range(_MAX_PAGES):
                # params=None, never {}: httpx *replaces* a URL's query string
                # with whatever ``params`` holds, so an empty dict would strip
                # the $skiptoken off @odata.nextLink and re-request page one
                # forever.
                resp = client.get(url, headers=headers, params=params or None)

                self._raise_for_status(resp)
                payload = resp.json()
                out.extend(payload.get("value", []))
                if len(out) >= limit:
                    break
                next_link = payload.get("@odata.nextLink")
                if not next_link:
                    break
                # nextLink already carries the query string; re-sending params
                # would duplicate $filter and make Graph 400.
                url, params = next_link, {}
        return out[:limit]

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.status_code < 400:
            return
        # Graph puts the actionable part in error.message; the body can be
        # large, so cap it rather than dumping a page of JSON into the log.
        detail = ""
        try:
            detail = str((resp.json().get("error") or {}).get("message", ""))[:400]
        except Exception:
            detail = resp.text[:400]
        if resp.status_code == 403:
            detail += (
                " (403 usually means the app registration is missing an "
                "application permission, or admin consent was never granted: "
                "SecurityIncident.Read.All / SecurityAlert.Read.All / "
                "ThreatHunting.Read.All)"
            )
        raise GraphApiError(
            f"Graph {resp.request.method} {resp.request.url.path} "
            f"failed with {resp.status_code}: {detail}",
            status_code=resp.status_code,
        )

    # -- security endpoints ----------------------------------------------

    def list_incidents(
        self,
        *,
        since: Optional[datetime] = None,
        limit: int = 100,
        expand_alerts: bool = True,
    ) -> List[Dict[str, Any]]:
        """XDR incidents updated at or after ``since``.

        Filters on ``lastUpdateDateTime``, not ``createdDateTime``: an incident
        the analyst cares about is often one created days ago that just gained
        a new alert, and a createdDateTime filter would never show it again.
        """
        params: Dict[str, Any] = {"$top": min(limit, 50)}
        if since is not None:
            params["$filter"] = f"lastUpdateDateTime ge {_graph_datetime(since)}"
        if expand_alerts:
            # One round trip instead of N. Graph rejects $expand=alerts
            # together with $top>50, which the min() above already respects.
            params["$expand"] = "alerts"
        return self._get_paged("/security/incidents", params, limit)

    def list_alerts(
        self, *, since: Optional[datetime] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """XDR unified alerts (``alerts_v2``) updated at or after ``since``."""
        params: Dict[str, Any] = {"$top": min(limit, 100)}
        if since is not None:
            params["$filter"] = f"lastUpdateDateTime ge {_graph_datetime(since)}"
        return self._get_paged("/security/alerts_v2", params, limit)

    def get_incident(self, incident_id: str) -> Dict[str, Any]:
        headers = self._headers()
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            resp = client.get(
                f"{self._base_url}/security/incidents/{incident_id}",
                headers=headers,
                params={"$expand": "alerts"},
            )
            self._raise_for_status(resp)
            return resp.json()

    def run_hunting_query(
        self, query: str, *, timespan: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run an advanced hunting (KQL) query.

        Returns Graph's ``{schema, results}`` shape unchanged — callers want
        the column schema, and normalizing it here would only lose information.
        ``timespan`` is an ISO-8601 interval (e.g. ``2024-01-01T00:00:00Z/
        2024-01-02T00:00:00Z``); omitted, Graph applies its own default window.
        """
        body: Dict[str, Any] = {"Query": query}
        if timespan:
            body["Timespan"] = timespan
        headers = self._headers()
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            resp = client.post(
                f"{self._base_url}/security/runHuntingQuery",
                headers=headers,
                json=body,
            )
            self._raise_for_status(resp)
            return resp.json()
