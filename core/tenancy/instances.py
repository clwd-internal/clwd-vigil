"""The registry of customer instances this deployment monitors.

An "instance" is one customer estate: an Entra tenant, its Sentinel workspace
and/or its Defender XDR subscription, and the Key Vault secrets that reach
them. Everything downstream — adapter names, ``federation_sources`` rows,
finding ids — is keyed on ``instance_id``, so this is the identifier that has
to be stable and strictly validated.

Storage is Postgres ``system_config`` under ``tenancy.instances``, for two
reasons. It is durable across Container Apps replica restarts, where a file in
the container filesystem is not; and the API replica and the daemon replica are
different processes on different machines, so a registration made through the
API has to be visible to the poller without a shared volume.

``VIGIL_TENANT_INSTANCES`` gives the infrastructure a way to declare instances
without an API call, which matters for the first boot of a fresh environment —
otherwise onboarding needs a human with a session cookie before any data flows.
Env-declared instances cannot be deleted through the API, because the next
restart would resurrect them and the operator would rightly conclude the delete
button is broken.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CONFIG_KEY = "tenancy.instances"
ENV_VAR = "VIGIL_TENANT_INSTANCES"

#: Supported vendors. Adding one means adding a VENDOR_FIELDS entry in
#: secrets.py and a VENDORS entry in adapters.py, so the list is explicit
#: rather than derived — a typo in a POST body should be a 400, not a
#: silently-registered adapter that never polls anything.
SUPPORTED_VENDORS = ("azure_sentinel", "microsoft_defender")

#: instance_id ends up inside an adapter name, a federation_sources primary
#: key, a Key Vault secret name and every finding's external_id. Key Vault is
#: the strictest of those: names are limited to alphanumerics and dashes.
#: 32 characters leaves room for the "tenant-" stem and "-subscription-id"
#: suffix inside Key Vault's 127-character limit.
_INSTANCE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")


class InvalidInstance(ValueError):
    """Rejected registration. Surfaces as a 400, never as a broken adapter."""


@dataclass(frozen=True)
class TenantInstance:
    instance_id: str
    vendors: tuple = ()
    key_vault_prefix: Optional[str] = None
    display_name: Optional[str] = None
    enabled: bool = True
    source: str = "api"  # "api" | "env"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "vendors": list(self.vendors),
            "key_vault_prefix": self.key_vault_prefix,
            "display_name": self.display_name,
            "enabled": self.enabled,
            "source": self.source,
            "metadata": dict(self.metadata),
        }


def validate_instance_id(instance_id: str) -> str:
    value = (instance_id or "").strip().lower()
    if not _INSTANCE_ID_RE.match(value):
        raise InvalidInstance(
            f"instance_id {instance_id!r} is invalid. Use 1-32 lowercase "
            "alphanumerics and dashes, starting and ending with an "
            "alphanumeric: it becomes part of a Key Vault secret name, a "
            "federation source id and every finding's external_id."
        )
    return value


def validate_vendors(vendors: Any) -> tuple:
    if not vendors:
        raise InvalidInstance(
            "at least one vendor is required; supported: "
            + ", ".join(SUPPORTED_VENDORS)
        )
    if isinstance(vendors, str):
        vendors = [vendors]
    out = []
    for vendor in vendors:
        name = str(vendor).strip().lower()
        if name not in SUPPORTED_VENDORS:
            raise InvalidInstance(
                f"unsupported vendor {vendor!r}; supported: "
                + ", ".join(SUPPORTED_VENDORS)
            )
        if name not in out:
            out.append(name)
    return tuple(out)


def _coerce(raw: Dict[str, Any], *, source: str) -> Optional[TenantInstance]:
    try:
        return TenantInstance(
            instance_id=validate_instance_id(raw.get("instance_id", "")),
            vendors=validate_vendors(raw.get("vendors")),
            key_vault_prefix=(raw.get("key_vault_prefix") or None),
            display_name=(raw.get("display_name") or None),
            enabled=bool(raw.get("enabled", True)),
            source=source,
            metadata=raw.get("metadata") or {},
        )
    except InvalidInstance as e:
        # One malformed entry must not hide the rest: a typo in the env var
        # would otherwise silently stop every customer from being polled.
        logger.error("ignoring invalid tenant instance (%s): %s", source, e)
        return None


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


def _from_env() -> List[TenantInstance]:
    raw = (os.environ.get(ENV_VAR) or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("%s is not valid JSON, ignoring: %s", ENV_VAR, e)
        return []
    if isinstance(parsed, dict):
        parsed = [{"instance_id": k, **(v or {})} for k, v in parsed.items()]
    if not isinstance(parsed, list):
        logger.error("%s must be a JSON list or object, ignoring", ENV_VAR)
        return []
    out = []
    for entry in parsed:
        if isinstance(entry, str):
            entry = {"instance_id": entry, "vendors": list(SUPPORTED_VENDORS)}
        if not isinstance(entry, dict):
            continue
        coerced = _coerce(entry, source="env")
        if coerced is not None:
            out.append(coerced)
    return out


def _read_store() -> Dict[str, Any]:
    try:
        from core.storage.config_service import get_config_service

        value = get_config_service().get_system_config(CONFIG_KEY)
        return value if isinstance(value, dict) else {}
    except Exception as e:
        # No database yet (unit tests, first boot before migrations). The env
        # bootstrap still works, which is the point of having it.
        logger.debug("tenancy.instances read failed: %s", e)
        return {}


def _write_store(value: Dict[str, Any], updated_by: str = "api") -> None:
    from core.storage.config_service import get_config_service

    get_config_service(user_id=updated_by).set_system_config(
        key=CONFIG_KEY,
        value=value,
        description="Registered customer instances for multi-tenant ingestion",
        config_type="tenancy",
    )


def _from_store() -> List[TenantInstance]:
    out = []
    for instance_id, raw in (_read_store() or {}).items():
        if not isinstance(raw, dict):
            continue
        coerced = _coerce({**raw, "instance_id": instance_id}, source="api")
        if coerced is not None:
            out.append(coerced)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_instances(include_disabled: bool = False) -> List[TenantInstance]:
    """Every registered instance, env bootstrap first, database second.

    A database entry with the same id wins: an operator changing a customer's
    vendors through the API should not be silently overridden by a stale env
    var from the last deployment.
    """
    merged: Dict[str, TenantInstance] = {i.instance_id: i for i in _from_env()}
    for instance in _from_store():
        merged[instance.instance_id] = instance
    out = sorted(merged.values(), key=lambda i: i.instance_id)
    if include_disabled:
        return out
    return [i for i in out if i.enabled]


def get_instance(instance_id: str) -> Optional[TenantInstance]:
    for instance in list_instances(include_disabled=True):
        if instance.instance_id == instance_id:
            return instance
    return None


def register_instance(
    instance_id: str,
    vendors: Any,
    *,
    key_vault_prefix: Optional[str] = None,
    display_name: Optional[str] = None,
    enabled: bool = True,
    metadata: Optional[Dict[str, Any]] = None,
    updated_by: str = "api",
) -> TenantInstance:
    """Create or replace an instance. Raises :class:`InvalidInstance` on bad
    input so the router can answer 400 rather than registering something that
    will fail obscurely at poll time."""
    instance = TenantInstance(
        instance_id=validate_instance_id(instance_id),
        vendors=validate_vendors(vendors),
        key_vault_prefix=key_vault_prefix or None,
        display_name=display_name or None,
        enabled=bool(enabled),
        source="api",
        metadata=metadata or {},
    )

    store = _read_store()
    store[instance.instance_id] = instance.to_dict()
    _write_store(store, updated_by=updated_by)

    from core.tenancy import secrets as tenancy_secrets

    # A re-registration usually follows a secret rotation. Without this the
    # new credentials would not take effect for up to the cache TTL and every
    # poll in between would fail auth.
    tenancy_secrets.reset_cache(instance.instance_id)

    return instance


def remove_instance(instance_id: str, updated_by: str = "api") -> bool:
    """Delete an instance. Returns False when it was not there.

    Deliberately does not delete the customer's findings or their
    ``federation_sources`` row. Removing an instance is an operational action
    (offboarding, a mistaken registration); destroying a customer's evidence
    trail is not something that should happen as a side effect of one DELETE.
    """
    instance = get_instance(instance_id)
    if instance is not None and instance.source == "env":
        raise InvalidInstance(
            f"instance {instance_id!r} is declared in {ENV_VAR} by the "
            "deployment and cannot be removed through the API; it would come "
            "back on the next restart. Remove it from the environment instead."
        )

    store = _read_store()
    if instance_id not in store:
        return False
    store.pop(instance_id)
    _write_store(store, updated_by=updated_by)

    from core.tenancy import secrets as tenancy_secrets

    tenancy_secrets.reset_cache(instance_id)
    return True


def source_id(vendor: str, instance_id: str) -> str:
    """The ``federation_sources`` primary key for one (vendor, instance) pair.

    ``<vendor>:<instance_id>``. Because ``register_adapter`` is keyed by name
    and that name is the ``federation_sources`` primary key, this alone gives
    each customer their own row, cursor, poll interval and enable toggle with
    no schema change.
    """
    return f"{vendor}:{instance_id}"


def parse_source_id(value: str) -> Optional[tuple]:
    """Inverse of :func:`source_id`; ``None`` for a non-instance source name."""
    if ":" not in value:
        return None
    vendor, _, instance_id = value.partition(":")
    if vendor not in SUPPORTED_VENDORS or not instance_id:
        return None
    return vendor, instance_id
