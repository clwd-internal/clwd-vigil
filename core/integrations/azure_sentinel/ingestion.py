"""
Azure Sentinel Ingestion Service - Ingest incidents from Azure Sentinel.

Fetches security incidents from Microsoft Sentinel (Azure Sentinel) and converts them to findings.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from core.config import get_integration_config
from core.ingestion.siem_ingestion_service import SIEMIngestionService
from core.integrations.azure_sentinel.descriptor import REQUIRED_FIELDS
from core.time import utcnow

logger = logging.getLogger(__name__)


class AzureSentinelIngestion(SIEMIngestionService):
    """Azure Sentinel ingestion service."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Azure Sentinel ingestion.

        FORK NOTE (docs/UPSTREAM.md): ``config`` is the whole multi-tenant
        seam. Upstream resolves one flat global dict from
        ``integrations_config.json``, which is correct for a single-tenant
        install and cannot express "this customer's Sentinel workspace". The
        argument defaults to exactly the upstream behaviour, so a zero-argument
        construction — which is what upstream's own adapter does — is unchanged.
        ``core.tenancy.adapters`` passes a per-instance dict resolved from Key
        Vault instead.
        """
        super().__init__()
        self.siem_name = "Azure Sentinel"
        self.config = (
            config if config is not None else get_integration_config("azure-sentinel")
        )

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Fetch incidents from Azure Sentinel.

        Args:
            start_time: Start time for incident query
            end_time: End time for incident query
            limit: Maximum number of incidents to fetch

        Returns:
            List of raw incident dictionaries
        """
        try:
            # FORK NOTE (docs/UPSTREAM.md): upstream caught ImportError around
            # this whole method and returned [], which made "azure-identity was
            # never installed" look exactly like "this tenant had no
            # incidents". A silent tenant is the worst failure mode a SOC has.
            # Both packages are declared in requirements.txt now, so reaching
            # this branch means a broken image and must be loud.
            try:

                from azure.identity import ClientSecretCredential
                from azure.mgmt.securityinsight import SecurityInsights
            except ImportError as exc:
                raise RuntimeError(
                    "Azure SDK missing for the Azure Sentinel integration "
                    f"({exc}). Install: pip install azure-identity "
                    "azure-mgmt-securityinsight (both are in requirements.txt)."
                ) from exc

            # Get config
            tenant_id = self.config.get("tenant_id")
            client_id = self.config.get("client_id")
            client_secret = self.config.get("client_secret")
            subscription_id = self.config.get("subscription_id")
            resource_group = self.config.get("resource_group")
            workspace_name = self.config.get("workspace_name")

            # REQUIRED_FIELDS is imported from the descriptor rather than
            # re-listed, so the guard and the configurable field set cannot
            # drift apart the way they had upstream.
            missing = [f for f in REQUIRED_FIELDS if not self.config.get(f)]
            if missing:
                logger.error(
                    "Azure Sentinel configuration incomplete; missing: %s",
                    ", ".join(missing),
                )
                return []

            # Authenticate
            credential = ClientSecretCredential(
                tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
            )

            # Create client
            client = SecurityInsights(credential, subscription_id)

            # Set time range
            if not start_time:
                start_time = utcnow() - timedelta(hours=24)
            if not end_time:
                end_time = utcnow()

            # Fetch incidents
            incidents = []
            incident_list = client.incidents.list(
                resource_group_name=resource_group, workspace_name=workspace_name
            )

            for incident in incident_list:
                # Filter by time
                if incident.created_time_utc:
                    if (
                        incident.created_time_utc < start_time
                        or incident.created_time_utc > end_time
                    ):
                        continue

                incidents.append(
                    {
                        "id": incident.name,
                        "title": incident.title,
                        "description": incident.description,
                        "severity": incident.severity,
                        "status": incident.status,
                        "created_time": (
                            incident.created_time_utc.isoformat()
                            if incident.created_time_utc
                            else None
                        ),
                        "last_updated_time": (
                            incident.last_updated_time_utc.isoformat()
                            if incident.last_updated_time_utc
                            else None
                        ),
                        "owner": incident.owner.email if incident.owner else None,
                        "labels": (
                            [label.label_name for label in incident.labels]
                            if incident.labels
                            else []
                        ),
                        "tactics": (
                            incident.additional_data.tactics
                            if incident.additional_data
                            else []
                        ),
                        "alert_count": (
                            incident.additional_data.alert_count
                            if incident.additional_data
                            else 0
                        ),
                        "properties": incident.additional_properties or {},
                    }
                )

                if len(incidents) >= limit:
                    break

            logger.info(f"Fetched {len(incidents)} incidents from Azure Sentinel")
            return incidents

        except Exception as e:
            # Deliberately re-raised, not swallowed into []. Returning [] is
            # how a credential rotation or a revoked app registration silently
            # stops one customer's ingest while the dashboard stays green.
            # The ERROR log above fires either way; raising also lets a caller
            # that does care (the instance API's connectivity probe, tests)
            # see the failure instead of an empty list.
            logger.error(f"Error fetching Azure Sentinel incidents: {e}")
            raise

    def transform_alert_to_finding(
        self, alert: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Transform Azure Sentinel incident to finding format.

        Args:
            alert: Raw incident from Azure Sentinel

        Returns:
            Finding dictionary
        """
        try:
            # Generate finding ID
            finding_id = f"sentinel-{alert.get('id', uuid.uuid4().hex[:12])}"

            # Extract entities
            entities = self.extract_entities(alert.get("properties", {}))

            # Build finding
            finding = {
                "finding_id": finding_id,
                "title": alert.get("title", "Azure Sentinel Incident"),
                "description": alert.get("description", ""),
                "severity": self.normalize_severity(alert.get("severity")),
                "data_source": "azure_sentinel",
                "timestamp": alert.get("created_time", utcnow().isoformat()),
                "raw_data": alert,
                "metadata": {
                    "incident_id": alert.get("id"),
                    "status": alert.get("status"),
                    "owner": alert.get("owner"),
                    "labels": alert.get("labels", []),
                    "tactics": alert.get("tactics", []),
                    "alert_count": alert.get("alert_count", 0),
                    "last_updated": alert.get("last_updated_time"),
                },
                "entities": entities,
                "mitre_attack": {
                    "tactics": alert.get("tactics", []),
                    "techniques": [],
                },
            }

            return finding

        except Exception as e:
            logger.error(f"Error transforming Azure Sentinel incident: {e}")
            return None
