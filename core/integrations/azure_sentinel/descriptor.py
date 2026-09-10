"""Azure Sentinel descriptor — source of truth for its registry entries.

FORK NOTE (see docs/UPSTREAM.md): upstream declared ``workspace_id``,
``tenant_id``, ``client_id`` and ``client_secret`` here, but ``ingestion.py``
reads ``tenant_id``, ``client_id``, ``client_secret``, ``subscription_id``,
``resource_group`` and ``workspace_name``, and guards on ``all([...])`` of
those six. Three of the six had no way to be populated, so the guard could
never pass and ``fetch_alerts`` always returned ``[]`` — Azure Sentinel
ingestion could not work at all. The field set below is what the Azure
management SDK actually needs:

* ``subscription_id`` / ``resource_group`` / ``workspace_name`` address the
  Log Analytics workspace that ``SecurityInsights.incidents.list`` is scoped to.
* ``workspace_id`` (the Log Analytics *GUID*) is a different value and is not
  what that call takes. It stays as an optional field because it is what the
  Log Analytics query API uses and operators recognise it.
"""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

#: The config keys ``AzureSentinelIngestion`` requires before it will call out.
#: Declared here so the ingestion guard and this descriptor cannot drift apart
#: again — ingestion imports this tuple rather than repeating the list.
REQUIRED_FIELDS = (
    "tenant_id",
    "client_id",
    "client_secret",
    "subscription_id",
    "resource_group",
    "workspace_name",
)

AZURE_SENTINEL = register_descriptor(
    IntegrationDescriptor(
        id="azure-sentinel",
        category="SIEM",
        mcp_server_names=("azure-sentinel",),
        fields=(
            IntegrationField("tenant_id"),
            IntegrationField("client_id"),
            IntegrationField("client_secret", secret=True),
            IntegrationField("subscription_id"),
            IntegrationField("resource_group"),
            IntegrationField("workspace_name"),
            # Log Analytics workspace GUID. Not used by incidents.list; kept
            # because operators have it to hand and the query API wants it.
            IntegrationField("workspace_id"),
        ),
    )
)
