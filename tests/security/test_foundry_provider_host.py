"""Azure AI Foundry as an OpenAI-type provider.

The plan was that Foundry would need no code change at all: register it as an
``openai``-type provider with ``base_url`` pointed at
``https://<account>.services.ai.azure.com/openai/v1`` and let the existing
OpenAI-compatible path do the work.

That was almost right. ``fetch_openai_models`` attaches the bearer token only
when ``SafeUrl.is_allowlisted_host`` is true — a deliberate SSRF mitigation, so
a misconfigured custom base_url cannot exfiltrate the configured key. A Foundry
account hostname is not in the built-in allowlist and cannot be, because it is
per-account. So discovery would go out unauthenticated and fail with a 401 that
looks like a bad API key rather than a missing allowlist entry.

``VIGIL_EXTRA_PROVIDER_HOSTS`` is the five-line fix, and these tests pin both
that it works and that it does not become a way to widen the allowlist from
anywhere other than the deployment's own environment.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.platform.url_safety import (  # noqa: E402
    DEFAULT_ALLOWED_PROVIDER_HOSTS,
    validate_provider_url,
)

pytestmark = pytest.mark.unit

FOUNDRY = "https://vigil-dev.services.ai.azure.com/openai/v1"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("VIGIL_EXTRA_PROVIDER_HOSTS", raising=False)


def test_a_foundry_host_is_not_trusted_by_default():
    """The built-in allowlist must not grow a wildcard for Azure: that would
    trust every Azure-hosted endpoint on the internet."""
    assert "vigil-dev.services.ai.azure.com" not in DEFAULT_ALLOWED_PROVIDER_HOSTS
    assert not any(h.endswith("azure.com") for h in DEFAULT_ALLOWED_PROVIDER_HOSTS)


def test_the_declared_foundry_host_gets_the_bearer_token(monkeypatch):
    """is_allowlisted_host is what decides whether discovery sends the key."""
    monkeypatch.setenv(
        "VIGIL_EXTRA_PROVIDER_HOSTS", "vigil-dev.services.ai.azure.com"
    )
    safe = validate_provider_url(FOUNDRY)
    assert safe.is_allowlisted_host is True
    # /models is appended by the caller onto the sanitized URL, so the /openai/v1
    # path has to survive validation intact.
    assert safe.sanitized == FOUNDRY


def test_the_builtin_hosts_still_work_once_the_variable_is_set(monkeypatch):
    monkeypatch.setenv("VIGIL_EXTRA_PROVIDER_HOSTS", "vigil-dev.services.ai.azure.com")
    assert validate_provider_url("https://api.openai.com/v1").is_allowlisted_host


def test_several_hosts_can_be_declared(monkeypatch):
    monkeypatch.setenv(
        "VIGIL_EXTRA_PROVIDER_HOSTS",
        " a.services.ai.azure.com , b.services.ai.azure.com ",
    )
    assert validate_provider_url("https://a.services.ai.azure.com/openai/v1").is_allowlisted_host
    assert validate_provider_url("https://b.services.ai.azure.com/openai/v1").is_allowlisted_host


def test_matching_is_exact_so_a_declared_host_does_not_trust_its_neighbours(
    monkeypatch,
):
    """No wildcards and no suffix matching: declaring one Foundry account must
    not trust another tenant's account on the same domain."""
    monkeypatch.setenv("VIGIL_EXTRA_PROVIDER_HOSTS", "vigil-dev.services.ai.azure.com")
    assert (
        "someone-else.services.ai.azure.com" not in DEFAULT_ALLOWED_PROVIDER_HOSTS
    )
    assert "services.ai.azure.com" not in DEFAULT_ALLOWED_PROVIDER_HOSTS
    assert (
        "evil-vigil-dev.services.ai.azure.com" not in DEFAULT_ALLOWED_PROVIDER_HOSTS
    )


def test_a_wildcard_entry_is_not_expanded(monkeypatch):
    """Someone will try this. It must match literally and therefore nothing."""
    monkeypatch.setenv("VIGIL_EXTRA_PROVIDER_HOSTS", "*.services.ai.azure.com")
    assert "vigil-dev.services.ai.azure.com" not in DEFAULT_ALLOWED_PROVIDER_HOSTS
    # The literal is all that is trusted, which is nothing reachable.
    assert "*.services.ai.azure.com" in DEFAULT_ALLOWED_PROVIDER_HOSTS


def test_an_empty_variable_changes_nothing(monkeypatch):
    monkeypatch.setenv("VIGIL_EXTRA_PROVIDER_HOSTS", "   ")
    assert set(DEFAULT_ALLOWED_PROVIDER_HOSTS) == {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
    }


def test_no_new_provider_type_is_needed():
    """Foundry is registered as an 'openai'-type provider with a base_url. If
    a fourth type ever appears for it, discovery.py and clients.py both need
    changes and this fork's Azure documentation is wrong."""
    from services.api.routers.llm_providers import VALID_PROVIDER_TYPES

    assert "openai" in VALID_PROVIDER_TYPES
    assert "azure" not in VALID_PROVIDER_TYPES
