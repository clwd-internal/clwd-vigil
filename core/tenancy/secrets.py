"""Per-instance credential resolution: Azure Key Vault, with a local fallback.

Upstream reads integration credentials from one flat JSON file. That cannot
serve several customers at once, and putting several customers' client secrets
in one file on a shared container filesystem would be a poor idea even if it
could.

In Azure, each customer instance's credentials live in Key Vault under a fixed
naming convention::

    tenant-<instance_id>-tenant-id
    tenant-<instance_id>-client-id
    tenant-<instance_id>-client-secret
    tenant-<instance_id>-subscription-id     (Sentinel only)
    tenant-<instance_id>-resource-group      (Sentinel only)
    tenant-<instance_id>-workspace-name      (Sentinel only)

The app reads them with its user-assigned managed identity; the infrastructure
sets ``AZURE_CLIENT_ID`` so ``DefaultAzureCredential`` picks the right one out
of the several identities a Container App can carry.

Two properties this module has to have:

**It must not hit Key Vault on every poll.** The federation poller runs a
Defender adapter every 60 seconds per customer. At 50 customers that is 300
Key Vault reads a minute for values that change perhaps twice a year, and Key
Vault is throttled per vault, not per caller. So: a TTL cache, default 15
minutes, and a negative cache so a customer who is half-provisioned does not
generate a retry storm.

**It must keep working with no Key Vault at all.** Local development, CI and
the existing docker-compose all have to keep running. With no vault URL
configured, resolution falls straight through to upstream's
``get_integration_config()``, so a single-instance local setup behaves exactly
as it does today.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

#: Config field -> Key Vault secret name suffix. Key Vault secret names allow
#: only alphanumerics and dashes, which is why these are dashed rather than
#: the snake_case the integrations use internally.
SECRET_SUFFIXES: Dict[str, str] = {
    "tenant_id": "tenant-id",
    "client_id": "client-id",
    "client_secret": "client-secret",
    "subscription_id": "subscription-id",
    "resource_group": "resource-group",
    "workspace_name": "workspace-name",
    "workspace_id": "workspace-id",
}

#: Fields fetched for every vendor. Anything else is vendor-specific and
#: fetched only when that vendor asks for it, so a Defender-only customer does
#: not log six "secret not found" warnings a poll.
BASE_FIELDS: Tuple[str, ...] = ("tenant_id", "client_id", "client_secret")

VENDOR_FIELDS: Dict[str, Tuple[str, ...]] = {
    "azure_sentinel": BASE_FIELDS
    + ("subscription_id", "resource_group", "workspace_name", "workspace_id"),
    "microsoft_defender": BASE_FIELDS,
}

#: Which upstream integration id a vendor falls back to when there is no vault.
FALLBACK_INTEGRATION_IDS: Dict[str, str] = {
    "azure_sentinel": "azure-sentinel",
    "microsoft_defender": "microsoft-defender",
}

DEFAULT_TTL_SECONDS = 900
DEFAULT_NEGATIVE_TTL_SECONDS = 60


def key_vault_url() -> Optional[str]:
    """The vault to read from, or ``None`` to use the file fallback.

    Read from the environment on every call rather than captured at import:
    ``Settings`` uses ``extra="ignore"``, so adding a field there would be a
    change to an upstream hot file for no gain, and a test that monkeypatches
    the environment should take effect immediately.
    """
    for var in ("VIGIL_KEY_VAULT_URL", "AZURE_KEY_VAULT_URL", "KEY_VAULT_URL"):
        value = (os.environ.get(var) or "").strip()  # noqa: ENV001 - Container Apps deployment boundary, not user config
        if value:
            return value
    return None


def _ttl() -> int:
    try:
        return max(0, int(os.environ.get("VIGIL_SECRET_CACHE_TTL", "")))  # noqa: ENV001 - Container Apps deployment boundary, not user config
    except ValueError:
        return DEFAULT_TTL_SECONDS


def secret_name(instance_id: str, field: str, prefix: Optional[str] = None) -> str:
    """``tenant-contoso-client-secret`` for instance ``contoso``, field
    ``client_secret``.

    ``prefix`` overrides the default ``tenant-<instance_id>`` stem, so an
    operator onboarding a customer whose secrets already exist under another
    naming scheme does not have to duplicate them.
    """
    suffix = SECRET_SUFFIXES.get(field, field.replace("_", "-"))
    stem = prefix or f"tenant-{instance_id}"
    return f"{stem.rstrip('-')}-{suffix}"


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class _TtlCache:
    """Small TTL cache. Threading lock, not asyncio: the Key Vault SDK is
    synchronous and the callers reach it through ``asyncio.to_thread``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at < time.monotonic():
                self._entries.pop(key, None)
                return None
            return dict(value)

    def put(self, key: str, value: Dict[str, Any], ttl: int) -> None:
        if ttl <= 0:
            return
        with self._lock:
            self._entries[key] = (time.monotonic() + ttl, dict(value))

    def invalidate(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._entries.clear()
            else:
                self._entries.pop(key, None)


_CACHE = _TtlCache()
_CLIENTS: Dict[str, Any] = {}
_CLIENT_LOCK = threading.Lock()


def reset_cache(instance_id: Optional[str] = None, vendor: Optional[str] = None) -> None:
    """Drop cached credentials.

    Called when an instance is registered or removed, and available to
    operators through the instances API after a secret rotation — otherwise a
    rotated secret would take up to the TTL to take effect and the intervening
    polls would all fail auth.
    """
    if instance_id is None:
        _CACHE.invalidate()
        return
    if vendor is None:
        for name in VENDOR_FIELDS:
            _CACHE.invalidate(f"{name}:{instance_id}")
        return
    _CACHE.invalidate(f"{vendor}:{instance_id}")


def _secret_client(vault_url: str):
    """One ``SecretClient`` per vault, reused.

    Constructing ``DefaultAzureCredential`` is expensive — it probes several
    credential sources — and the managed identity token it caches internally
    is the thing we want to keep warm.
    """
    with _CLIENT_LOCK:
        client = _CLIENTS.get(vault_url)
        if client is not None:
            return client

        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as e:  # pragma: no cover - dependency is pinned
            raise RuntimeError(
                "Key Vault credential resolution needs azure-identity and "
                "azure-keyvault-secrets. Install them "
                "(pip install -r requirements.txt), or unset the key vault URL "
                "to fall back to file-based integration config."
            ) from e

        # managed_identity_client_id is what makes a *user-assigned* identity
        # work. With several identities attached to one Container App, IMDS
        # cannot guess which one is meant and returns a 400 that surfaces
        # much later as an opaque 403 from Key Vault.
        credential = DefaultAzureCredential(
            managed_identity_client_id=os.environ.get("AZURE_CLIENT_ID") or None,  # noqa: ENV001 - Container Apps deployment boundary, not user config
            exclude_interactive_browser_credential=True,
        )
        client = SecretClient(vault_url=vault_url, credential=credential)
        _CLIENTS[vault_url] = client
        return client


def _reset_clients() -> None:
    """Test hook — the client caches a credential and therefore a vault URL."""
    with _CLIENT_LOCK:
        _CLIENTS.clear()


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _from_key_vault(
    vault_url: str, instance_id: str, fields: Tuple[str, ...], prefix: Optional[str]
) -> Dict[str, Any]:
    client = _secret_client(vault_url)
    resolved: Dict[str, Any] = {}
    for field in fields:
        name = secret_name(instance_id, field, prefix)
        try:
            secret = client.get_secret(name)
        except Exception as e:
            # A missing optional secret is normal (workspace_id is optional for
            # Sentinel), so this is not an error on its own. The caller decides
            # whether the resulting dict is complete enough to use, and says so
            # by naming the fields it still needs.
            logger.debug("key vault: %s unavailable (%s)", name, type(e).__name__)
            continue
        value = getattr(secret, "value", None)
        if value:
            resolved[field] = value
    return resolved


def _from_file(vendor: str) -> Dict[str, Any]:
    from core.config import get_integration_config

    integration_id = FALLBACK_INTEGRATION_IDS.get(vendor, vendor.replace("_", "-"))
    config = get_integration_config(integration_id)
    return dict(config) if isinstance(config, dict) else {}


def resolve_config(
    instance_id: str,
    vendor: str,
    *,
    key_vault_prefix: Optional[str] = None,
    refresh: bool = False,
) -> Dict[str, Any]:
    """Credentials for one (customer instance, vendor) pair.

    Returns ``{}`` rather than raising when nothing resolves: the caller is an
    adapter factory whose ``is_configured()`` check is allowed to answer "not
    yet", and a half-provisioned customer must not stop the other customers'
    adapters from being constructed.
    """
    cache_key = f"{vendor}:{instance_id}"
    if not refresh:
        cached = _CACHE.get(cache_key)
        if cached is not None:
            return cached

    fields = VENDOR_FIELDS.get(vendor, BASE_FIELDS)
    vault_url = key_vault_url()

    if vault_url:
        try:
            resolved = _from_key_vault(vault_url, instance_id, fields, key_vault_prefix)
        except Exception as e:
            # Vault unreachable, identity misconfigured, network policy wrong.
            # Cache the emptiness briefly so a 60-second Defender poll across
            # every customer does not turn one outage into a retry storm.
            logger.error(
                "key vault resolution failed for instance=%s vendor=%s: %s",
                instance_id,
                vendor,
                e,
            )
            _CACHE.put(cache_key, {}, DEFAULT_NEGATIVE_TTL_SECONDS)
            return {}
        ttl = _ttl() if resolved else DEFAULT_NEGATIVE_TTL_SECONDS
        _CACHE.put(cache_key, resolved, ttl)
        return dict(resolved)

    # No vault: local development and the existing docker-compose. Upstream's
    # file config has no notion of an instance, so every instance sees the same
    # credentials. That is fine for one developer with one lab tenant and is
    # exactly why the isolation in adapters.py keys on instance_id rather than
    # on the credentials themselves.
    resolved = _from_file(vendor)
    _CACHE.put(cache_key, resolved, min(_ttl(), 60))
    return dict(resolved)


def missing_fields(config: Dict[str, Any], required: Tuple[str, ...]) -> list[str]:
    """Which required fields are absent or blank. Named, not counted: "config
    incomplete" gives an operator nothing to go and fix."""
    return [f for f in required if not (config or {}).get(f)]
