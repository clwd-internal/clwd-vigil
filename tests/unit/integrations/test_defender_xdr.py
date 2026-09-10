"""Microsoft Defender XDR ingestion — the Graph surface, not the MDE one.

FORK-OWNED (docs/UPSTREAM.md). Upstream's Defender integration reads device
alerts from Defender for Endpoint. This fork reads Defender XDR through
Microsoft Graph, so these tests pin the three things that would be silently
wrong if someone "restored" the MDE behaviour during an upstream merge:

1. the host and paths actually called,
2. the ``alerts_v2`` evidence model (which is polymorphic, unlike MDE's flat
   ``entityType``), and
3. that a failure raises rather than returning an empty list — an empty list
   from a SIEM poller is indistinguishable from a quiet tenant.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import respx

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.integrations.microsoft_defender.graph import (  # noqa: E402
    DefenderXdrClient,
    GraphApiError,
    GraphAuthError,
    _graph_datetime,
)
from core.integrations.microsoft_defender.ingestion import (  # noqa: E402
    MicrosoftDefenderIngestion,
)

pytestmark = pytest.mark.unit

GRAPH = "https://graph.microsoft.com/v1.0"
CREDS = {"tenant_id": "tid", "client_id": "cid", "client_secret": "sec"}


@pytest.fixture
def no_token(monkeypatch):
    """Skip MSAL. Token acquisition is Microsoft's code path, not ours."""
    monkeypatch.setattr(
        DefenderXdrClient, "_headers", lambda self: {"Authorization": "Bearer at"}
    )


def _service(config=None):
    return MicrosoftDefenderIngestion(config={**CREDS, **(config or {})})


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


@respx.mock
async def test_incidents_come_from_graph_not_defender_for_endpoint(no_token):
    route = respx.get(f"{GRAPH}/security/incidents").mock(
        return_value=httpx.Response(200, json={"value": [{"id": "1"}]})
    )
    # If anything still reaches MDE, respx raises on the unmocked host, which
    # is exactly the regression signal we want.
    items = await _service().fetch_alerts(
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc), limit=10
    )

    assert [i["id"] for i in items] == ["1"]
    url = str(route.calls.last.request.url)
    assert "graph.microsoft.com" in url
    assert "securitycenter.microsoft.com" not in url
    # lastUpdateDateTime, not createdDateTime: an incident that gains a new
    # alert days after creation must reappear.
    assert "lastUpdateDateTime+ge+2026-01-01T00%3A00%3A00Z" in url.replace(
        "%20", "+"
    ) or "lastUpdateDateTime ge 2026-01-01T00:00:00Z" in httpx.URL(url).params.get(
        "$filter", ""
    )


@respx.mock
async def test_alerts_resource_uses_alerts_v2_not_legacy_alerts(no_token):
    route = respx.get(f"{GRAPH}/security/alerts_v2").mock(
        return_value=httpx.Response(200, json={"value": [{"id": "a1"}]})
    )
    await _service({"resource": "alerts"}).fetch_alerts(limit=5)
    assert route.called
    assert route.calls.last.request.url.path == "/v1.0/security/alerts_v2"


@respx.mock
async def test_hunting_query_posts_to_run_hunting_query(no_token):
    route = respx.post(f"{GRAPH}/security/runHuntingQuery").mock(
        return_value=httpx.Response(200, json={"schema": [], "results": []})
    )
    out = await _service().run_hunting_query(
        "DeviceProcessEvents | take 1", timespan="P1D"
    )
    assert out == {"schema": [], "results": []}
    import json as _json

    assert _json.loads(route.calls.last.request.content) == {
        "Query": "DeviceProcessEvents | take 1",
        "Timespan": "P1D",
    }


@respx.mock
async def test_paging_follows_odata_next_link_without_resending_filter(no_token):
    pages = [
        httpx.Response(
            200,
            json={
                "value": [{"id": "1"}],
                "@odata.nextLink": f"{GRAPH}/security/incidents?%24skiptoken=abc",
            },
        ),
        httpx.Response(200, json={"value": [{"id": "2"}]}),
    ]
    route = respx.get(f"{GRAPH}/security/incidents").mock(side_effect=pages)

    items = await _service().fetch_alerts(
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc), limit=10
    )

    assert [i["id"] for i in items] == ["1", "2"]
    assert route.call_count == 2
    second = route.calls[1].request.url
    assert second.params.get("$skiptoken") == "abc"
    # nextLink already carries the original query; re-sending $filter would
    # duplicate it and Graph answers 400.
    assert "$filter" not in second.params


@respx.mock
async def test_limit_bounds_the_result_even_when_graph_returns_more(no_token):
    respx.get(f"{GRAPH}/security/incidents").mock(
        return_value=httpx.Response(
            200, json={"value": [{"id": str(i)} for i in range(50)]}
        )
    )
    items = await _service().fetch_alerts(limit=3)
    assert len(items) == 3


# --------------------------------------------------------------------------
# Failure is loud
# --------------------------------------------------------------------------


@respx.mock
async def test_a_403_raises_rather_than_looking_like_a_quiet_tenant(no_token):
    respx.get(f"{GRAPH}/security/incidents").mock(
        return_value=httpx.Response(
            403, json={"error": {"message": "Insufficient privileges"}}
        )
    )
    with pytest.raises(GraphApiError) as exc:
        await _service().fetch_alerts(limit=5)
    assert exc.value.status_code == 403
    # The message has to name the permissions, or the operator has nothing to
    # act on: the token is issued fine, so the failure only shows at call time.
    assert "SecurityIncident.Read.All" in str(exc.value)


async def test_missing_credentials_raise_auth_error_not_empty_list():
    service = MicrosoftDefenderIngestion(config={"tenant_id": "tid"})
    with pytest.raises(GraphAuthError) as exc:
        await service.fetch_alerts(limit=5)
    assert "client_id" in str(exc.value)
    assert "client_secret" in str(exc.value)


def test_graph_datetime_never_emits_an_offset_and_a_z():
    """Graph rejects '+00:00Z' with a parse error rather than ignoring it."""
    aware = datetime(2026, 5, 4, 3, 2, 1, 999999, tzinfo=timezone.utc)
    assert _graph_datetime(aware) == "2026-05-04T03:02:01Z"
    naive = datetime(2026, 5, 4, 3, 2, 1)
    assert _graph_datetime(naive) == "2026-05-04T03:02:01Z"


# --------------------------------------------------------------------------
# Transform
# --------------------------------------------------------------------------

_INCIDENT = {
    "id": "1234",
    "displayName": "Multi-stage incident involving Initial access",
    "severity": "high",
    "status": "active",
    "createdDateTime": "2026-01-01T00:00:00Z",
    "lastUpdateDateTime": "2026-01-02T00:00:00Z",
    "incidentWebUrl": "https://security.microsoft.com/incident/1234",
    "alerts": [
        {
            "id": "alert-1",
            "title": "Suspicious PowerShell",
            "category": "Execution",
            "serviceSource": "microsoftDefenderForEndpoint",
            "mitreTechniques": ["T1059.001"],
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.deviceEvidence",
                    "deviceDnsName": "ws-01.contoso.test",
                    "ipInterfaces": ["10.0.0.5"],
                },
                {
                    "@odata.type": "#microsoft.graph.security.userEvidence",
                    "userAccount": {"userPrincipalName": "jane@contoso.test"},
                },
                {
                    "@odata.type": "#microsoft.graph.security.fileEvidence",
                    "fileDetails": {"sha256": "abc123"},
                },
                {
                    "@odata.type": "#microsoft.graph.security.ipEvidence",
                    "ipAddress": "203.0.113.9",
                },
                # An evidence type we do not model must be ignored, not guessed.
                {"@odata.type": "#microsoft.graph.security.somethingNew", "x": 1},
            ],
        }
    ],
}


def test_incident_transform_flattens_the_alerts_v2_evidence_model():
    finding = _service().transform_alert_to_finding(_INCIDENT)

    assert finding["external_id"] == "1234"
    assert finding["data_source"] == "microsoft_defender"
    assert finding["severity"] == "high"
    assert finding["entities"]["hostnames"] == ["ws-01.contoso.test"]
    assert finding["entities"]["usernames"] == ["jane@contoso.test"]
    assert finding["entities"]["file_hashes"] == ["abc123"]
    assert sorted(finding["entities"]["ip_addresses"]) == ["10.0.0.5", "203.0.113.9"]
    assert finding["mitre_attack"]["techniques"] == ["T1059.001"]
    assert finding["metadata"]["alert_count"] == 1
    # XDR incidents carry no description of their own; rolling the alert titles
    # up saves the triage agent a round trip.
    assert "Suspicious PowerShell" in finding["description"]


def test_external_id_is_the_native_id_not_the_prefixed_finding_id():
    """external_id is half of the (data_source, external_id) dedup key.

    SIEMIngestionAdapter will reverse-engineer it out of finding_id when it is
    absent; setting it explicitly means the dedup key does not depend on a
    string-prefix coincidence.
    """
    finding = _service().transform_alert_to_finding(_INCIDENT)
    assert finding["finding_id"] == "defender-1234"
    assert finding["external_id"] == "1234"


def test_alert_transform_selected_by_the_resource_field():
    alert = {
        "id": "a-9",
        "title": "Malware detected",
        "severity": "medium",
        "category": "Malware",
        "createdDateTime": "2026-02-02T00:00:00Z",
        "incidentId": "77",
        "evidence": [],
    }
    finding = _service({"resource": "alerts"}).transform_alert_to_finding(alert)
    assert finding["external_id"] == "a-9"
    assert finding["metadata"]["incident_id"] == "77"
    assert finding["metadata"]["resource"] == "alerts"


def test_an_unknown_resource_value_falls_back_to_incidents():
    assert _service({"resource": "nonsense"}).resource == "incidents"
