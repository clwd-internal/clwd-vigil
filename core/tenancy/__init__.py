"""Multi-tenant seam for a fork that runs one deployment per customer estate.

Upstream Vigil is single-tenant by construction: ``get_integration_config(id)``
reads one flat dict out of ``~/.vigil/integrations_config.json``, and each
vendor adapter registers itself under a fixed literal name. That is correct for
the product it is — a SOC team watching its own estate.

This fork runs a managed SOC: one deployment, many customer estates, each with
its own Entra tenant and its own credentials. Everything needed to make that
safe lives in this package, and nothing outside it changes except a five-line
import hook in ``core/federation/registry.py``. See ``docs/UPSTREAM.md``.

The three pieces:

``secrets``    resolves one customer instance's credentials, from Azure Key
               Vault in Azure and from the existing config file locally.
``instances``  the durable registry of which customers exist.
``adapters``   registers one federation adapter per (customer, vendor) pair and
               — the part that matters — namespaces every finding it produces
               so two customers' data can never collide.
"""

from __future__ import annotations

__all__ = ["adapters", "instances", "secrets"]
