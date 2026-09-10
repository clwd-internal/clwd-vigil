"""One federation adapter per (customer instance, vendor) pair.

This is the correctness-critical module of the fork.

``register_adapter(name, factory)`` is keyed by name, and that name becomes the
``federation_sources`` primary key. Registering ``azure_sentinel:contoso`` and
``azure_sentinel:fabrikam`` therefore gives each customer their own row, cursor,
poll interval and enable/disable toggle, with no schema change and no edit to
the federation package beyond a five-line import hook.

What that does **not** give us is data separation, and this is the part that
would be a customer-facing incident rather than a bug:

    Two different Entra tenants both have a Defender XDR incident numbered 1.
    Findings are deduplicated on ``finding_id`` (the primary key) and on the
    unique index over ``(data_source, external_id)``. Upstream's Defender
    service produces ``finding_id="defender-1"`` and ``external_id="1"`` for
    both. The second customer's incident is then swallowed as a duplicate of
    the first, and whichever analyst opens it sees the other customer's alert
    titles, hostnames and usernames.

So every finding a per-instance adapter emits is renamespaced here.

Why not simply pass a different ``external_id_prefix`` to
``SIEMIngestionAdapter``? Because that parameter does not do what its name
suggests. It *strips*: ``fetch()`` uses it to reverse-engineer ``external_id``
out of ``finding_id`` when the service left it blank. It never prepends
anything, and it is not consulted at all once ``external_id`` is set. Nothing
upstream namespaces a finding.

The namespacing scheme, and why:

``external_id``  ``<instance_id>:<native_id>``. Human-readable, greppable, and
                 comfortably inside ``String(255)``.

``finding_id``   ``<vendor_prefix>-<sha256(instance_id|native_id)[:32]>``.
                 The primary key column is ``String(50)`` — a hard ceiling.
                 ``sentinel-<GUID>`` is already ~45 characters, so prefixing an
                 instance id onto it would overflow and silently truncate,
                 which would reintroduce exactly the collision this module
                 exists to prevent. A digest is fixed-width, deterministic
                 across polls and processes (no PYTHONHASHSEED dependence), and
                 leaves the vendor prefix legible at the front.

``data_source``  deliberately left unscoped (``azure_sentinel``, not
                 ``azure_sentinel:contoso``). It drives existing UI filters and
                 severity rules; the instance travels in ``metadata`` and in
                 ``external_id`` instead.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Callable, Dict, List, Optional

from core.federation.adapters._siem_base import SIEMIngestionAdapter
from core.federation.contract import FederationAdapter, register_adapter
from core.tenancy import secrets as tenancy_secrets
from core.tenancy.instances import TenantInstance, list_instances, source_id

logger = logging.getLogger(__name__)

#: Digest length. 32 hex characters is 128 bits: with a vendor prefix of up to
#: 17 characters it fits String(50), and a collision needs ~2^64 findings.
_DIGEST_CHARS = 32


class _VendorSpec:
    __slots__ = ("integration_id", "finding_prefix", "default_interval", "required")

    def __init__(
        self,
        integration_id: str,
        finding_prefix: str,
        default_interval: int,
        required: tuple,
    ) -> None:
        self.integration_id = integration_id
        self.finding_prefix = finding_prefix
        self.default_interval = default_interval
        self.required = required


VENDORS: Dict[str, _VendorSpec] = {
    "azure_sentinel": _VendorSpec(
        integration_id="azure-sentinel",
        finding_prefix="sentinel",
        default_interval=300,  # cloud SIEM cadence, matches upstream
        required=(
            "tenant_id",
            "client_id",
            "client_secret",
            "subscription_id",
            "resource_group",
            "workspace_name",
        ),
    ),
    "microsoft_defender": _VendorSpec(
        integration_id="microsoft-defender",
        finding_prefix="defender",
        default_interval=60,  # EDR cadence, matches upstream
        required=("tenant_id", "client_id", "client_secret"),
    ),
}


def _build_service(vendor: str, config: Dict[str, Any]):
    """Construct the vendor's ingestion service with an explicit config.

    Both services grew an optional ``config=`` argument in this fork precisely
    so they can be handed a per-instance dict instead of reaching for the one
    global file. Imported lazily: importing every vendor service at module
    scope would pull the Azure SDK into processes that never ingest anything.
    """
    if vendor == "azure_sentinel":
        from core.integrations.azure_sentinel.ingestion import AzureSentinelIngestion

        return AzureSentinelIngestion(config=config)
    if vendor == "microsoft_defender":
        from core.integrations.microsoft_defender.ingestion import (
            MicrosoftDefenderIngestion,
        )

        return MicrosoftDefenderIngestion(config=config)
    raise ValueError(f"unknown vendor {vendor!r}")


def scoped_finding_id(vendor: str, instance_id: str, native_id: str) -> str:
    """Deterministic, collision-resistant, and short enough for String(50)."""
    prefix = VENDORS[vendor].finding_prefix if vendor in VENDORS else vendor
    digest = hashlib.sha256(
        f"{instance_id}|{native_id}".encode("utf-8")
    ).hexdigest()[:_DIGEST_CHARS]
    return f"{prefix}-{digest}"


def scoped_external_id(instance_id: str, native_id: str) -> str:
    return f"{instance_id}:{native_id}"


def native_id_of(finding: Dict[str, Any], vendor: str) -> str:
    """The source-native identifier inside a finding the vendor service built.

    ``external_id`` when the service set it (this fork's Defender service
    does), otherwise the vendor prefix stripped off ``finding_id``. Falling
    back to the whole ``finding_id`` is safe — it is still unique within the
    customer, which is all the namespacing needs.
    """
    native = (finding.get("external_id") or "").strip()
    if native:
        return native
    fid = str(finding.get("finding_id") or "")
    prefix = f"{VENDORS[vendor].finding_prefix}-" if vendor in VENDORS else ""
    if prefix and fid.startswith(prefix):
        return fid[len(prefix) :]
    return fid


class _ScopedService:
    """Wraps a vendor ingestion service and namespaces what it emits.

    A wrapper rather than a subclass, and rather than a change to
    ``_siem_base.py``: the vendor services are upstream files that change
    often, and the whole point of this fork's structure is that a rebase
    conflict lands in fork-owned code.
    """

    def __init__(self, vendor: str, instance: TenantInstance, inner: Any) -> None:
        self._vendor = vendor
        self._instance = instance
        self._inner = inner

    def __getattr__(self, item: str) -> Any:
        # Anything we do not namespace (run_hunting_query, config, ...) passes
        # through, so the wrapper does not have to track the service's surface.
        return getattr(self._inner, item)

    async def fetch_alerts(self, **kwargs) -> List[Dict[str, Any]]:
        return await self._inner.fetch_alerts(**kwargs)

    def transform_alert_to_finding(
        self, alert: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        finding = self._inner.transform_alert_to_finding(alert)
        if not finding:
            return finding
        return self.scope(finding)

    def scope(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        instance_id = self._instance.instance_id
        native = native_id_of(finding, self._vendor)

        finding["finding_id"] = scoped_finding_id(self._vendor, instance_id, native)
        finding["external_id"] = scoped_external_id(instance_id, native)

        metadata = finding.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        # The native id has to survive somewhere: it is what an analyst types
        # into the Defender or Sentinel portal, and the digest above is
        # one-way.
        metadata.update(
            {
                "instance_id": instance_id,
                "source_instance": source_id(self._vendor, instance_id),
                "native_id": native,
            }
        )
        if self._instance.display_name:
            metadata["instance_name"] = self._instance.display_name
        finding["metadata"] = metadata
        return finding


class TenantScopedAdapter(SIEMIngestionAdapter):
    """``SIEMIngestionAdapter`` whose configuration check is per-instance.

    Upstream's ``is_configured()`` asks ``is_integration_enabled(integration_id)``,
    which reads the one global file. For a Key Vault-backed instance that file
    does not exist, so the base implementation would answer False for every
    customer and nothing would ever poll.
    """

    def __init__(self, *, vendor: str, instance: TenantInstance, **kwargs) -> None:
        super().__init__(**kwargs)
        self.vendor = vendor
        self.instance = instance

    def is_configured(self) -> bool:
        spec = VENDORS[self.vendor]
        config = tenancy_secrets.resolve_config(
            self.instance.instance_id,
            self.vendor,
            key_vault_prefix=self.instance.key_vault_prefix,
        )
        missing = tenancy_secrets.missing_fields(config, spec.required)
        if missing:
            logger.info(
                "instance %s vendor %s not configured; missing: %s",
                self.instance.instance_id,
                self.vendor,
                ", ".join(missing),
            )
            return False
        return True


def build_adapter(vendor: str, instance: TenantInstance) -> FederationAdapter:
    spec = VENDORS[vendor]

    def make_service():
        config = tenancy_secrets.resolve_config(
            instance.instance_id,
            vendor,
            key_vault_prefix=instance.key_vault_prefix,
        )
        return _ScopedService(vendor, instance, _build_service(vendor, config))

    return TenantScopedAdapter(
        vendor=vendor,
        instance=instance,
        name=source_id(vendor, instance.instance_id),
        integration_id=spec.integration_id,
        default_interval=spec.default_interval,
        service_factory=make_service,
        # Never consulted: _ScopedService always sets external_id. Passed so
        # the base class contract is satisfied and so a future upstream change
        # that starts using it has a sane value.
        external_id_prefix=spec.finding_prefix,
    )


def register_instance_adapters(
    instances: Optional[List[TenantInstance]] = None,
) -> List[str]:
    """Register one adapter per (instance, vendor). Returns the names.

    Called from ``core.federation.registry._ensure_builtins_loaded`` through a
    guarded import, so a failure here degrades to "no per-instance adapters"
    rather than taking down the whole federation registry.
    """
    registered: List[str] = []
    for instance in instances if instances is not None else list_instances():
        for vendor in instance.vendors:
            if vendor not in VENDORS:
                logger.warning(
                    "instance %s declares unknown vendor %s; skipping",
                    instance.instance_id,
                    vendor,
                )
                continue
            name = source_id(vendor, instance.instance_id)
            register_adapter(name, _factory_for(vendor, instance))
            registered.append(name)
    if registered:
        logger.info(
            "Registered %d per-instance federation adapter(s): %s",
            len(registered),
            ", ".join(registered),
        )
    return registered


def _factory_for(vendor: str, instance: TenantInstance) -> Callable[[], FederationAdapter]:
    def _factory() -> FederationAdapter:
        return build_adapter(vendor, instance)

    return _factory
