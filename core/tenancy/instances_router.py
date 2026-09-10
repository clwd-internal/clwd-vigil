"""Customer instance registration API.

``POST /api/integrations/instances`` with
``{"instance_id": ..., "vendors": [...], "key_vault_prefix": ...}``, which is
the contract the infrastructure runbook in ``clwd-internal/clwd-soc`` already
documents. GET and DELETE round it out.

Mounted by ``services/api/discovery.py`` purely by existing here with a
``ROUTER_META``; no edit to ``services/api/main.py`` is needed. Auth is the
default authenticated-user dependency, because a list of a managed SOC's
customers is itself sensitive.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.routing import Auth, RouterMeta
from core.tenancy import secrets as tenancy_secrets
from core.tenancy.adapters import VENDORS
from core.tenancy.instances import (
    SUPPORTED_VENDORS,
    InvalidInstance,
    get_instance,
    list_instances,
    register_instance,
    remove_instance,
    source_id,
)

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/integrations/instances",
    tags=["integrations", "tenancy"],
    auth=Auth.REQUIRED,
)


class InstanceCreate(BaseModel):
    instance_id: str = Field(
        ...,
        description=(
            "Stable customer identifier. Lowercase alphanumerics and dashes, "
            "1-32 characters. Becomes part of the Key Vault secret names, the "
            "federation source id and every finding's external_id, so it "
            "cannot be changed after data has been ingested."
        ),
    )
    vendors: List[str] = Field(
        ..., description=f"One or more of: {', '.join(SUPPORTED_VENDORS)}"
    )
    key_vault_prefix: Optional[str] = Field(
        None,
        description=(
            "Overrides the default 'tenant-<instance_id>' secret name stem. "
            "Leave unset unless the customer's secrets already exist under "
            "another naming scheme."
        ),
    )
    display_name: Optional[str] = None
    enabled: bool = True
    metadata: Optional[Dict[str, Any]] = None


def _status(instance) -> Dict[str, Any]:
    """Instance plus, per vendor, whether its credentials actually resolve.

    Returning only the registration would let an operator believe onboarding
    succeeded when the Key Vault secrets are missing — the failure would
    otherwise surface as an empty federation source hours later.
    """
    out = instance.to_dict()
    vendor_status = {}
    for vendor in instance.vendors:
        spec = VENDORS.get(vendor)
        if spec is None:
            vendor_status[vendor] = {"configured": False, "missing": ["unknown vendor"]}
            continue
        try:
            config = tenancy_secrets.resolve_config(
                instance.instance_id,
                vendor,
                key_vault_prefix=instance.key_vault_prefix,
            )
            missing = tenancy_secrets.missing_fields(config, spec.required)
        except Exception as e:
            logger.warning(
                "credential probe failed for %s/%s: %s", instance.instance_id, vendor, e
            )
            vendor_status[vendor] = {"configured": False, "error": str(e)}
            continue
        vendor_status[vendor] = {
            "configured": not missing,
            "missing": missing,
            "source_id": source_id(vendor, instance.instance_id),
        }
    out["vendor_status"] = vendor_status
    return out


@router.get("")
async def list_registered_instances(include_disabled: bool = True):
    instances = list_instances(include_disabled=include_disabled)
    return {
        "instances": [_status(i) for i in instances],
        "count": len(instances),
        "key_vault": tenancy_secrets.key_vault_url() or None,
    }


@router.post("", status_code=201)
async def create_instance(payload: InstanceCreate):
    try:
        instance = register_instance(
            payload.instance_id,
            payload.vendors,
            key_vault_prefix=payload.key_vault_prefix,
            display_name=payload.display_name,
            enabled=payload.enabled,
            metadata=payload.metadata,
        )
    except InvalidInstance as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error("instance registration failed: %s", e)
        raise HTTPException(status_code=500, detail="registration failed") from e

    return {
        **_status(instance),
        # The poller builds its task set once at boot, so a brand new instance
        # is not polled until the daemon restarts. Saying so here is cheaper
        # than an operator filing a bug about an instance that never ingests.
        "note": (
            "Registered. The federation source row is created and polled after "
            "the daemon next starts."
        ),
    }


@router.get("/{instance_id}")
async def read_instance(instance_id: str):
    instance = get_instance(instance_id)
    if instance is None:
        raise HTTPException(status_code=404, detail="instance not found")
    return _status(instance)


@router.delete("/{instance_id}")
async def delete_instance(instance_id: str):
    try:
        removed = remove_instance(instance_id)
    except InvalidInstance as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    if not removed:
        raise HTTPException(status_code=404, detail="instance not found")
    return {
        "instance_id": instance_id,
        "removed": True,
        "note": (
            "Findings and the federation_sources row are intentionally left in "
            "place; deleting a customer's evidence trail is a separate, "
            "deliberate action."
        ),
    }


@router.post("/{instance_id}/refresh-credentials")
async def refresh_credentials(instance_id: str):
    """Drop the cached secrets for one instance after a rotation.

    Without this a rotated client secret takes up to VIGIL_SECRET_CACHE_TTL
    (15 minutes by default) to take effect, and every poll in between fails
    authentication against the customer's tenant.
    """
    instance = get_instance(instance_id)
    if instance is None:
        raise HTTPException(status_code=404, detail="instance not found")
    tenancy_secrets.reset_cache(instance_id)
    return _status(instance)
