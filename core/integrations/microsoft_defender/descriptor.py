"""Microsoft Defender XDR descriptor — source of truth for its registry entries.

FORK NOTE (docs/UPSTREAM.md): the credential triple is unchanged from upstream,
but what it authenticates against is not. Upstream requested the Defender for
Endpoint scope (``https://api.securitycenter.microsoft.com/.default``); this
fork requests Microsoft Graph (``https://graph.microsoft.com/.default``) so it
can read Defender XDR.

The Entra app registration needs these **application** permissions (client
credentials, no user context) with admin consent granted:

    SecurityIncident.Read.All   ->  GET  /security/incidents
    SecurityAlert.Read.All      ->  GET  /security/alerts_v2
    ThreatHunting.Read.All      ->  POST /security/runHuntingQuery

A 403 from any of those three almost always means the permission was added but
consent was never granted — the token is issued either way, so the failure only
shows up at call time.
"""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

# Re-exported from the Graph client so the "is it configured" guard and the
# configurable field set cannot drift apart.
from core.integrations.microsoft_defender.graph import (  # noqa: F401
    REQUIRED_FIELDS,
)

MICROSOFT_DEFENDER = register_descriptor(
    IntegrationDescriptor(
        id="microsoft-defender",
        category="EDR",
        mcp_server_names=("microsoft-defender",),
        fields=(
            IntegrationField("tenant_id"),
            IntegrationField("client_id"),
            IntegrationField("client_secret", secret=True),
            # "incidents" (default) or "alerts". Which XDR surface this tenant
            # ingests as findings; see ingestion.py.
            IntegrationField("resource"),
        ),
    )
)
