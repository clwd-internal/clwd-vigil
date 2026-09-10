import sys
from pathlib import Path

# Spawned as ``python3 core/integrations/<vendor>/tool.py`` with a narrowed env,
# so the repo root is not on sys.path and PYTHONPATH is not forwarded. Add it
# here so the ``core.*`` imports below resolve; otherwise they fail at spawn.
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import asyncio
import json
import logging

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from core.integrations._base.config import resolve
from core.integrations.microsoft_defender.descriptor import MICROSOFT_DEFENDER
from core.integrations.microsoft_defender.graph import (
    REQUIRED_FIELDS,
    DefenderXdrClient,
)

logger = logging.getLogger(__name__)


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def _client():
    """Build a Graph client from the configured credentials, or None.

    FORK NOTE (docs/UPSTREAM.md): upstream minted a Defender **for Endpoint**
    token here (scope ``https://api.securitycenter.microsoft.com/.default``)
    and called ``api.securitycenter.microsoft.com/api``. This fork talks to
    Defender **XDR** through Microsoft Graph, matching the ingestion service
    and the application permissions the Entra app is actually granted:
    SecurityIncident.Read.All, SecurityAlert.Read.All, ThreatHunting.Read.All.
    """
    config = resolve(MICROSOFT_DEFENDER)
    missing = [f for f in REQUIRED_FIELDS if not config.get(f)]
    if missing:
        return None
    return DefenderXdrClient(config)


async def handle_list_tools():
    return [
        types.Tool(
            name="xdr_get_incidents",
            description=(
                "List Microsoft Defender XDR incidents (correlated across "
                "endpoint, identity, email and cloud apps), newest updates first."
            ),
            inputSchema={
                "type": "object",
                "properties": {"limit": {"type": "integer", "default": 20}},
                "required": [],
            },
        ),
        types.Tool(
            name="xdr_get_incident",
            description="Get one Defender XDR incident with its alerts expanded",
            inputSchema={
                "type": "object",
                "properties": {"incident_id": {"type": "string"}},
                "required": ["incident_id"],
            },
        ),
        types.Tool(
            name="xdr_get_alerts",
            description="List Defender XDR unified alerts (alerts_v2)",
            inputSchema={
                "type": "object",
                "properties": {"limit": {"type": "integer", "default": 20}},
                "required": [],
            },
        ),
        types.Tool(
            name="xdr_run_hunting_query",
            description=(
                "Run an advanced hunting KQL query against Defender XDR. "
                "Read-only; requires ThreatHunting.Read.All."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "timespan": {
                        "type": "string",
                        "description": "ISO-8601 interval, e.g. 2024-01-01T00:00:00Z/2024-01-02T00:00:00Z",
                    },
                },
                "required": ["query"],
            },
        ),
    ]


async def handle_call_tool(name: str, arguments: dict | None):
    client = _client()
    if client is None:
        return result({"error": "Microsoft Defender XDR not configured"})

    args = arguments or {}

    try:
        if name == "xdr_get_incidents":
            incidents = client.list_incidents(
                limit=int(args.get("limit", 20)), expand_alerts=False
            )
            return result(
                {
                    "count": len(incidents),
                    "incidents": [
                        {
                            "id": i.get("id"),
                            "displayName": i.get("displayName"),
                            "severity": i.get("severity"),
                            "status": i.get("status"),
                            "createdDateTime": i.get("createdDateTime"),
                            "lastUpdateDateTime": i.get("lastUpdateDateTime"),
                        }
                        for i in incidents
                    ],
                }
            )

        elif name == "xdr_get_incident":
            incident_id = args.get("incident_id")
            if not incident_id:
                return result({"error": "incident_id required"})
            return result({"incident": client.get_incident(str(incident_id))})

        elif name == "xdr_get_alerts":
            alerts = client.list_alerts(limit=int(args.get("limit", 20)))
            return result(
                {
                    "count": len(alerts),
                    "alerts": [
                        {
                            "id": a.get("id"),
                            "title": a.get("title"),
                            "severity": a.get("severity"),
                            "status": a.get("status"),
                            "category": a.get("category"),
                            "serviceSource": a.get("serviceSource"),
                            "incidentId": a.get("incidentId"),
                        }
                        for a in alerts
                    ],
                }
            )

        elif name == "xdr_run_hunting_query":
            query = args.get("query")
            if not query:
                return result({"error": "query required"})
            return result(
                client.run_hunting_query(str(query), timespan=args.get("timespan"))
            )

        return result({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return result({"error": str(e)})


async def _on_list_tools(_ctx, _params):
    return types.ListToolsResult(tools=await handle_list_tools())


async def _on_call_tool(_ctx, params):
    try:
        content = await handle_call_tool(params.name, params.arguments)
    except Exception as exc:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=str(exc))],
            is_error=True,
        )
    return types.CallToolResult(content=content)


server = Server(
    "microsoft-defender",
    on_list_tools=_on_list_tools,
    on_call_tool=_on_call_tool,
)


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="microsoft-defender",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
