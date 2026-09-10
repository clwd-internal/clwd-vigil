"""
Microsoft Defender XDR ingestion service.

FORK NOTE (docs/UPSTREAM.md): upstream fetched alerts from Defender **for
Endpoint** (``https://api.securitycenter.microsoft.com/api/alerts``, scope
``https://api.securitycenter.microsoft.com/.default``). That is the
device-level product. This fork targets Defender **XDR** through Microsoft
Graph, because XDR is where cross-product correlation happens — one incident
spanning endpoint, identity, email and cloud apps — and because MDE serves
neither ``alerts_v2`` nor advanced hunting.

The HTTP details live in ``core.integrations.microsoft_defender.graph`` (a
new, fork-owned file), so this module stays a thin normaliser and the Graph
surface can also be reached from the MCP tool server without duplication.

Two ingest shapes are supported and selected by the ``resource`` config field:

* ``incidents`` (default) — one finding per XDR incident. This is the unit an
  analyst works, and it carries its alerts inline via ``$expand=alerts``.
* ``alerts``              — one finding per ``alerts_v2`` alert, for tenants
  that want raw alert volume rather than correlated incidents.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from core.config import get_integration_config
from core.ingestion.siem_ingestion_service import SIEMIngestionService
from core.integrations.microsoft_defender.graph import (
    DefenderXdrClient,
    GraphApiError,
    GraphAuthError,
)
from core.time import utcnow

logger = logging.getLogger(__name__)

#: Config values for the ``resource`` field.
RESOURCE_INCIDENTS = "incidents"
RESOURCE_ALERTS = "alerts"


class MicrosoftDefenderIngestion(SIEMIngestionService):
    """Microsoft Defender XDR ingestion service."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Microsoft Defender XDR ingestion.

        ``config`` is the multi-tenant seam (see the Azure Sentinel service for
        the same pattern). It defaults to upstream's global-file lookup, so a
        zero-argument construction behaves exactly as before;
        ``core.tenancy.adapters`` passes a per-customer dict resolved from Key
        Vault instead.
        """
        super().__init__()
        self.siem_name = "Microsoft Defender XDR"
        self.config = (
            config
            if config is not None
            else get_integration_config("microsoft-defender")
        )
        self._client: Optional[DefenderXdrClient] = None

    # -- plumbing ---------------------------------------------------------

    @property
    def client(self) -> DefenderXdrClient:
        if self._client is None:
            self._client = DefenderXdrClient(self.config)
        return self._client

    @property
    def resource(self) -> str:
        raw = str(self.config.get("resource") or RESOURCE_INCIDENTS).strip().lower()
        return raw if raw in (RESOURCE_INCIDENTS, RESOURCE_ALERTS) else RESOURCE_INCIDENTS

    # -- fetch ------------------------------------------------------------

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Fetch XDR incidents (or alerts_v2 alerts) from Microsoft Graph.

        ``end_time`` is accepted for interface compatibility but not sent to
        Graph: the filter is on ``lastUpdateDateTime ge <start>``, and an upper
        bound would drop incidents that were updated between the query being
        built and it being served.
        """
        if start_time is None:
            start_time = utcnow() - timedelta(hours=24)

        # Both the MSAL token exchange and the Graph calls are blocking HTTP;
        # this method is async by interface, so offload the whole thing rather
        # than blocking the daemon's event loop for the duration of a poll.
        def _call() -> List[Dict[str, Any]]:
            if self.resource == RESOURCE_ALERTS:
                return self.client.list_alerts(since=start_time, limit=limit)
            return self.client.list_incidents(since=start_time, limit=limit)

        try:
            items = await asyncio.to_thread(_call)
        except (GraphAuthError, GraphApiError) as e:
            # Logged at ERROR and re-raised rather than swallowed into []. An
            # empty list here is indistinguishable from a quiet tenant, which
            # is how an expired client secret goes unnoticed for a week.
            logger.error("%s fetch failed: %s", self.siem_name, e)
            raise

        logger.info(
            "Fetched %d %s from %s", len(items), self.resource, self.siem_name
        )
        return items

    async def run_hunting_query(
        self, query: str, *, timespan: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run an advanced hunting (KQL) query against this tenant.

        Exposed on the ingestion service (rather than only on the MCP tool) so
        the per-instance adapters give each customer a hunting surface bound to
        their own credentials — a hunt must never be able to run against
        another tenant's telemetry.
        """
        return await asyncio.to_thread(
            self.client.run_hunting_query, query, timespan=timespan
        )

    # -- transform --------------------------------------------------------

    def transform_alert_to_finding(
        self, item: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Transform an XDR incident or alert into Vigil's finding shape."""
        try:
            if self.resource == RESOURCE_ALERTS:
                return self._transform_alert(item)
            return self._transform_incident(item)
        except Exception as e:
            logger.error("Error transforming %s item: %s", self.siem_name, e)
            return None

    def _transform_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        native_id = str(incident.get("id") or uuid.uuid4().hex[:12])
        alerts = incident.get("alerts") or []

        entities = _empty_entities()
        tactics: List[str] = []
        techniques: List[str] = []
        for alert in alerts:
            _merge_entities(entities, _entities_from_alert(alert))
            for t in alert.get("mitreTechniques") or []:
                if t not in techniques:
                    techniques.append(t)
            category = alert.get("category")
            if category and category not in tactics:
                tactics.append(category)

        return {
            "finding_id": f"defender-{native_id}",
            # Set explicitly rather than left for SIEMIngestionAdapter to
            # reverse-engineer out of finding_id. external_id is half of the
            # (data_source, external_id) dedup key, so it should be the
            # source-native id and nothing else.
            "external_id": native_id,
            "title": incident.get("displayName") or "Defender XDR Incident",
            "description": _incident_description(incident, alerts),
            "severity": self.normalize_severity(incident.get("severity")),
            "data_source": "microsoft_defender",
            "timestamp": incident.get("createdDateTime") or utcnow().isoformat(),
            "raw_data": incident,
            "metadata": {
                "incident_id": native_id,
                "incident_web_url": incident.get("incidentWebUrl"),
                "status": incident.get("status"),
                "classification": incident.get("classification"),
                "determination": incident.get("determination"),
                "assigned_to": incident.get("assignedTo"),
                "tenant_id": incident.get("tenantId"),
                "alert_count": len(alerts),
                "alert_ids": [a.get("id") for a in alerts if a.get("id")],
                "service_sources": sorted(
                    {a.get("serviceSource") for a in alerts if a.get("serviceSource")}
                ),
                "last_updated": incident.get("lastUpdateDateTime"),
                "resource": RESOURCE_INCIDENTS,
            },
            "entities": entities,
            "mitre_attack": {"tactics": tactics, "techniques": techniques},
        }

    def _transform_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        native_id = str(alert.get("id") or uuid.uuid4().hex[:12])
        return {
            "finding_id": f"defender-{native_id}",
            "external_id": native_id,
            "title": alert.get("title") or "Defender XDR Alert",
            "description": alert.get("description") or "",
            "severity": self.normalize_severity(alert.get("severity")),
            "data_source": "microsoft_defender",
            "timestamp": alert.get("createdDateTime") or utcnow().isoformat(),
            "raw_data": alert,
            "metadata": {
                "alert_id": native_id,
                "incident_id": alert.get("incidentId"),
                "alert_web_url": alert.get("alertWebUrl"),
                "category": alert.get("category"),
                "status": alert.get("status"),
                "classification": alert.get("classification"),
                "determination": alert.get("determination"),
                "assigned_to": alert.get("assignedTo"),
                "detection_source": alert.get("detectionSource"),
                "service_source": alert.get("serviceSource"),
                "threat_family_name": alert.get("threatFamilyName"),
                "first_activity": alert.get("firstActivityDateTime"),
                "last_activity": alert.get("lastActivityDateTime"),
                "resource": RESOURCE_ALERTS,
            },
            "entities": _entities_from_alert(alert),
            "mitre_attack": {
                "tactics": [alert["category"]] if alert.get("category") else [],
                "techniques": list(alert.get("mitreTechniques") or []),
            },
        }


# ---------------------------------------------------------------------------
# Entity extraction
#
# alerts_v2 replaced MDE's flat ``evidence[].entityType`` with a polymorphic
# ``evidence[]`` discriminated by ``@odata.type``. The shapes below are the
# ones that carry entities the triage agents pivot on; unknown evidence types
# are ignored rather than guessed at.
# ---------------------------------------------------------------------------

_EVIDENCE_IP = "#microsoft.graph.security.ipEvidence"
_EVIDENCE_URL = "#microsoft.graph.security.urlEvidence"
_EVIDENCE_USER = "#microsoft.graph.security.userEvidence"
_EVIDENCE_DEVICE = "#microsoft.graph.security.deviceEvidence"
_EVIDENCE_FILE = "#microsoft.graph.security.fileEvidence"
_EVIDENCE_PROCESS = "#microsoft.graph.security.processEvidence"
_EVIDENCE_MAILBOX = "#microsoft.graph.security.mailboxEvidence"


def _empty_entities() -> Dict[str, List[str]]:
    return {
        "ip_addresses": [],
        "domains": [],
        "usernames": [],
        "hostnames": [],
        "file_hashes": [],
    }


def _add(bucket: List[str], value: Any) -> None:
    if value and value not in bucket:
        bucket.append(str(value))


def _merge_entities(target: Dict[str, List[str]], extra: Dict[str, List[str]]) -> None:
    for key, values in extra.items():
        for value in values:
            _add(target.setdefault(key, []), value)


def _file_details(details: Optional[Dict[str, Any]], entities: Dict[str, List[str]]):
    for key in ("sha256", "sha1"):
        _add(entities["file_hashes"], (details or {}).get(key))


def _entities_from_alert(alert: Dict[str, Any]) -> Dict[str, List[str]]:
    entities = _empty_entities()
    for item in alert.get("evidence") or []:
        odata_type = item.get("@odata.type")

        if odata_type == _EVIDENCE_IP:
            _add(entities["ip_addresses"], item.get("ipAddress"))
        elif odata_type == _EVIDENCE_URL:
            _add(entities["domains"], item.get("url"))
        elif odata_type == _EVIDENCE_USER:
            account = item.get("userAccount") or {}
            _add(
                entities["usernames"],
                account.get("userPrincipalName") or account.get("accountName"),
            )
        elif odata_type == _EVIDENCE_DEVICE:
            _add(entities["hostnames"], item.get("deviceDnsName"))
            for addr in item.get("ipInterfaces") or []:
                _add(entities["ip_addresses"], addr)
        elif odata_type == _EVIDENCE_FILE:
            _file_details(item.get("fileDetails"), entities)
        elif odata_type == _EVIDENCE_PROCESS:
            _file_details(item.get("imageFile"), entities)
            account = item.get("userAccount") or {}
            _add(
                entities["usernames"],
                account.get("userPrincipalName") or account.get("accountName"),
            )
        elif odata_type == _EVIDENCE_MAILBOX:
            _add(entities["usernames"], item.get("userAccount", {}).get(
                "userPrincipalName"
            ))
    return entities


def _incident_description(
    incident: Dict[str, Any], alerts: List[Dict[str, Any]]
) -> str:
    """Synthesize a description.

    XDR incidents have no description field of their own — only a
    ``displayName`` and their constituent alerts. Rolling the alert titles up
    here means the triage agent sees what the incident is made of without
    another Graph round trip.
    """
    if not alerts:
        return incident.get("displayName") or ""
    titles = []
    for alert in alerts[:10]:
        title = alert.get("title")
        if title and title not in titles:
            titles.append(title)
    suffix = f" (+{len(alerts) - 10} more alerts)" if len(alerts) > 10 else ""
    return "Correlated alerts: " + "; ".join(titles) + suffix
