"""Multi-tenant isolation. The test that matters most in this fork.

Upstream Vigil watches one estate, so a finding's identity is the vendor's own
id. This fork watches many, and two customers' Entra tenants both number their
first Defender XDR incident 1.

Findings are deduplicated twice over: ``finding_id`` is the primary key, and
there is a UNIQUE index over ``(data_source, external_id)``. If both customers'
incident 1 produces ``finding_id="defender-1"`` and ``external_id="1"``, the
second customer's incident is discarded as a duplicate of the first, and the
analyst who opens it is shown another customer's hostnames, usernames and alert
titles. That is a data-separation incident, not a bug report.

So the load-bearing assertions here are the ones that show the *same upstream
id from two instances yields two distinct records*, on both dedup keys.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.tenancy import secrets as tenancy_secrets  # noqa: E402
from core.tenancy.adapters import (  # noqa: E402
    VENDORS,
    _ScopedService,
    build_adapter,
    native_id_of,
    register_instance_adapters,
    scoped_finding_id,
)
from core.tenancy.instances import (  # noqa: E402
    InvalidInstance,
    TenantInstance,
    parse_source_id,
    source_id,
    validate_instance_id,
    validate_vendors,
)

pytestmark = pytest.mark.unit

CONTOSO = TenantInstance(
    instance_id="contoso", vendors=("microsoft_defender",), display_name="Contoso Ltd"
)
FABRIKAM = TenantInstance(instance_id="fabrikam", vendors=("microsoft_defender",))

# The finding upstream's Defender service builds for XDR incident 1. Identical
# for both customers, because the id space is per-tenant.
def _upstream_finding():
    return {
        "finding_id": "defender-1",
        "external_id": "1",
        "title": "Multi-stage incident",
        "severity": "high",
        "data_source": "microsoft_defender",
        "metadata": {"resource": "incidents"},
    }


class _FakeService:
    """Stands in for the vendor ingestion service."""

    def __init__(self, finding=None):
        self._finding = finding if finding is not None else _upstream_finding()
        self.config = {"tenant_id": "t"}

    async def fetch_alerts(self, **kwargs):
        return [{"id": "1"}]

    def transform_alert_to_finding(self, alert):
        return dict(self._finding) if self._finding is not None else None

    def run_hunting_query(self, query):  # pragma: no cover - passthrough probe
        return {"query": query}


def _scope(instance, finding=None):
    svc = _ScopedService("microsoft_defender", instance, _FakeService(finding))
    return svc.transform_alert_to_finding({"id": "1"})


# ---------------------------------------------------------------------------
# The isolation proof
# ---------------------------------------------------------------------------


def test_same_upstream_incident_id_from_two_instances_yields_two_records():
    a = _scope(CONTOSO)
    b = _scope(FABRIKAM)

    # Primary key.
    assert a["finding_id"] != b["finding_id"]
    # The (data_source, external_id) UNIQUE index. data_source is deliberately
    # the same for both, so external_id is the only thing keeping them apart.
    assert a["data_source"] == b["data_source"] == "microsoft_defender"
    assert a["external_id"] != b["external_id"]

    # And the pair as the database sees it.
    assert (a["data_source"], a["external_id"]) != (b["data_source"], b["external_id"])


def test_the_unscoped_finding_would_have_collided():
    """Guards the premise: without scoping these are byte-identical.

    If upstream ever starts namespacing findings itself this test fails, and
    whoever sees it should check whether this module is still needed rather
    than deleting the assertion.
    """
    a, b = _upstream_finding(), _upstream_finding()
    assert a["finding_id"] == b["finding_id"]
    assert (a["data_source"], a["external_id"]) == (b["data_source"], b["external_id"])


def test_scoping_is_stable_across_polls_and_processes():
    """Dedup depends on the same incident producing the same id every poll.

    A digest built from anything process-local (id(), hash() under a random
    PYTHONHASHSEED, a timestamp) would re-ingest every incident on every poll
    and every replica.
    """
    first = _scope(CONTOSO)
    second = _scope(CONTOSO)
    assert first["finding_id"] == second["finding_id"]
    assert first["external_id"] == second["external_id"]
    assert (
        scoped_finding_id("microsoft_defender", "contoso", "1")
        == "defender-" + __import__("hashlib")
        .sha256(b"contoso|1")
        .hexdigest()[:32]
    )


def test_finding_id_fits_the_string50_primary_key_even_for_a_sentinel_guid():
    """finding_id is String(50). 'sentinel-<GUID>' is already ~45 characters,
    so a naive '<instance>:' prefix would overflow and truncate — and a
    truncated id collides, which is the failure this module prevents."""
    guid = "12345678-1234-1234-1234-1234567890ab"
    fid = scoped_finding_id("azure_sentinel", "a-very-long-customer-name-here", guid)
    assert len(fid) <= 50
    assert fid.startswith("sentinel-")


def test_external_id_fits_string255_and_stays_readable():
    finding = _scope(CONTOSO)
    assert finding["external_id"] == "contoso:1"
    assert len(finding["external_id"]) <= 255


def test_the_native_id_survives_so_an_analyst_can_pivot_to_the_portal():
    """The digest is one-way; without this the vendor's own id is unrecoverable
    and nobody can look the incident up in the Defender portal."""
    finding = _scope(CONTOSO)
    assert finding["metadata"]["native_id"] == "1"
    assert finding["metadata"]["instance_id"] == "contoso"
    assert finding["metadata"]["source_instance"] == "microsoft_defender:contoso"
    assert finding["metadata"]["instance_name"] == "Contoso Ltd"
    # Pre-existing metadata is preserved, not replaced.
    assert finding["metadata"]["resource"] == "incidents"


def test_scoping_works_when_the_service_leaves_external_id_unset():
    """Sentinel's service sets only finding_id. The prefix is stripped back off
    rather than being embedded twice."""
    finding = {
        "finding_id": "sentinel-abc",
        "data_source": "azure_sentinel",
    }
    svc = _ScopedService("azure_sentinel", CONTOSO, _FakeService(finding))
    scoped = svc.transform_alert_to_finding({})
    assert scoped["external_id"] == "contoso:abc"
    assert scoped["metadata"]["native_id"] == "abc"


def test_native_id_falls_back_to_the_whole_finding_id():
    """An unrecognised convention still isolates: finding_id is unique within
    the customer, which is all the namespacing needs."""
    assert native_id_of({"finding_id": "weird-format"}, "azure_sentinel") == (
        "weird-format"
    )


def test_a_falsy_transform_result_is_passed_through_not_scoped():
    svc = _ScopedService("microsoft_defender", CONTOSO, _FakeService(None))
    svc._inner._finding = None
    assert svc.transform_alert_to_finding({}) is None


def test_unknown_attributes_pass_through_to_the_wrapped_service():
    svc = _ScopedService("microsoft_defender", CONTOSO, _FakeService())
    assert svc.run_hunting_query("q") == {"query": "q"}
    assert svc.config == {"tenant_id": "t"}


# ---------------------------------------------------------------------------
# Adapter naming — this is what gives each customer its own federation row
# ---------------------------------------------------------------------------


def test_each_instance_gets_its_own_federation_source_id():
    assert source_id("azure_sentinel", "contoso") == "azure_sentinel:contoso"
    assert parse_source_id("azure_sentinel:contoso") == ("azure_sentinel", "contoso")
    # An upstream builtin adapter name must not be mistaken for an instance.
    assert parse_source_id("azure_sentinel") is None
    assert parse_source_id("nonsense:contoso") is None


def test_register_instance_adapters_registers_one_adapter_per_pair(monkeypatch):
    from core.federation import contract

    monkeypatch.setattr(contract, "_ADAPTER_FACTORIES", {})
    import core.tenancy.adapters as tenancy_adapters

    monkeypatch.setattr(
        tenancy_adapters,
        "register_adapter",
        lambda name, factory: contract._ADAPTER_FACTORIES.__setitem__(name, factory),
    )

    names = register_instance_adapters(
        [
            TenantInstance(
                instance_id="contoso",
                vendors=("azure_sentinel", "microsoft_defender"),
            ),
            TenantInstance(instance_id="fabrikam", vendors=("azure_sentinel",)),
        ]
    )
    assert sorted(names) == [
        "azure_sentinel:contoso",
        "azure_sentinel:fabrikam",
        "microsoft_defender:contoso",
    ]


def test_an_unknown_vendor_is_skipped_rather_than_registered(monkeypatch):
    registered = []
    import core.tenancy.adapters as tenancy_adapters

    monkeypatch.setattr(
        tenancy_adapters, "register_adapter", lambda n, f: registered.append(n)
    )
    names = register_instance_adapters(
        [TenantInstance(instance_id="c", vendors=("microsoft_defender", "nope"))]
    )
    assert names == ["microsoft_defender:c"]
    assert registered == ["microsoft_defender:c"]


def test_adapter_is_configured_reflects_the_instance_not_the_global_file(monkeypatch):
    """Upstream's is_configured() reads the one global integrations file. Under
    Key Vault that file does not exist, so the base implementation would answer
    False for every customer and nothing would ever poll."""
    import core.tenancy.adapters as tenancy_adapters

    resolved = {"contoso": {"tenant_id": "t", "client_id": "c", "client_secret": "s"}}
    monkeypatch.setattr(
        tenancy_adapters.tenancy_secrets,
        "resolve_config",
        lambda instance_id, vendor, **kw: resolved.get(instance_id, {}),
    )

    assert build_adapter("microsoft_defender", CONTOSO).is_configured() is True
    assert build_adapter("microsoft_defender", FABRIKAM).is_configured() is False


def test_sentinel_requires_the_six_fields_ingestion_actually_reads():
    """The upstream bug this fork fixed: the descriptor collected four fields
    while ingestion guarded on six, three of which were undeclarable."""
    assert VENDORS["azure_sentinel"].required == (
        "tenant_id",
        "client_id",
        "client_secret",
        "subscription_id",
        "resource_group",
        "workspace_name",
    )


# ---------------------------------------------------------------------------
# instance_id validation — it lands in four different namespaces
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["contoso", "a", "c-1", "customer-42", "a" * 32])
def test_valid_instance_ids(value):
    assert validate_instance_id(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "-leading",
        "trailing-",
        "Upper",  # normalised to lowercase, but only after the dash rules
        "with space",
        "with_underscore",  # Key Vault secret names reject underscores
        "with:colon",  # would break parse_source_id
        "a" * 33,
        "../escape",
    ],
)
def test_invalid_instance_ids_are_rejected(value):
    if value == "Upper":
        # Case is normalised rather than rejected; the point is that the result
        # is lowercase, because Key Vault secret names are case-insensitive but
        # our source ids are not.
        assert validate_instance_id(value) == "upper"
        return
    with pytest.raises(InvalidInstance):
        validate_instance_id(value)


def test_vendor_validation_rejects_typos_rather_than_registering_a_dead_adapter():
    assert validate_vendors(["microsoft_defender"]) == ("microsoft_defender",)
    assert validate_vendors("azure_sentinel") == ("azure_sentinel",)
    # Duplicates collapse, so a double registration cannot happen.
    assert validate_vendors(["azure_sentinel", "azure_sentinel"]) == ("azure_sentinel",)
    with pytest.raises(InvalidInstance):
        validate_vendors([])
    with pytest.raises(InvalidInstance):
        validate_vendors(["azure_sentinal"])


# ---------------------------------------------------------------------------
# Secret naming and caching
# ---------------------------------------------------------------------------


def test_key_vault_secret_names_match_the_infrastructure_convention():
    assert (
        tenancy_secrets.secret_name("contoso", "client_secret")
        == "tenant-contoso-client-secret"
    )
    assert (
        tenancy_secrets.secret_name("contoso", "subscription_id")
        == "tenant-contoso-subscription-id"
    )
    assert (
        tenancy_secrets.secret_name("contoso", "workspace_name", "kv-custom")
        == "kv-custom-workspace-name"
    )


def test_resolution_is_cached_so_a_60s_poll_does_not_hammer_key_vault(monkeypatch):
    calls = []
    monkeypatch.setenv("VIGIL_KEY_VAULT_URL", "https://kv.test/")
    tenancy_secrets.reset_cache()

    def fake(vault_url, instance_id, fields, prefix):
        calls.append(instance_id)
        return {"tenant_id": "t", "client_id": "c", "client_secret": "s"}

    monkeypatch.setattr(tenancy_secrets, "_from_key_vault", fake)

    for _ in range(5):
        tenancy_secrets.resolve_config("contoso", "microsoft_defender")
    assert calls == ["contoso"]

    # Two customers must not share a cache entry.
    tenancy_secrets.resolve_config("fabrikam", "microsoft_defender")
    assert calls == ["contoso", "fabrikam"]

    # A rotation invalidates.
    tenancy_secrets.reset_cache("contoso")
    tenancy_secrets.resolve_config("contoso", "microsoft_defender")
    assert calls == ["contoso", "fabrikam", "contoso"]
    tenancy_secrets.reset_cache()


def test_a_key_vault_outage_returns_empty_rather_than_raising(monkeypatch):
    """The caller is an adapter factory. One customer's vault failure must not
    stop the other customers' adapters from being constructed."""
    monkeypatch.setenv("VIGIL_KEY_VAULT_URL", "https://kv.test/")
    tenancy_secrets.reset_cache()
    monkeypatch.setattr(
        tenancy_secrets,
        "_from_key_vault",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("vault down")),
    )
    assert tenancy_secrets.resolve_config("contoso", "microsoft_defender") == {}
    tenancy_secrets.reset_cache()


def test_no_key_vault_falls_back_to_the_existing_file_config(monkeypatch):
    """Local development, CI and the existing docker-compose keep working."""
    for var in ("VIGIL_KEY_VAULT_URL", "AZURE_KEY_VAULT_URL", "KEY_VAULT_URL"):
        monkeypatch.delenv(var, raising=False)
    tenancy_secrets.reset_cache()
    monkeypatch.setattr(
        tenancy_secrets,
        "_from_file",
        lambda vendor: {"tenant_id": "file-t", "client_id": "c", "client_secret": "s"},
    )
    config = tenancy_secrets.resolve_config("contoso", "microsoft_defender")
    assert config["tenant_id"] == "file-t"
    tenancy_secrets.reset_cache()


def test_missing_fields_names_them_rather_than_counting_them():
    assert tenancy_secrets.missing_fields(
        {"tenant_id": "t", "client_id": ""}, ("tenant_id", "client_id", "client_secret")
    ) == ["client_id", "client_secret"]


def test_the_cache_never_returns_a_shared_mutable_dict(monkeypatch):
    """A caller mutating the returned config must not poison every later
    resolution for that customer."""
    monkeypatch.setenv("VIGIL_KEY_VAULT_URL", "https://kv.test/")
    tenancy_secrets.reset_cache()
    monkeypatch.setattr(
        tenancy_secrets, "_from_key_vault", lambda *a, **kw: {"tenant_id": "t"}
    )
    first = tenancy_secrets.resolve_config("contoso", "microsoft_defender")
    first["tenant_id"] = "mutated"
    second = tenancy_secrets.resolve_config("contoso", "microsoft_defender")
    assert second["tenant_id"] == "t"
    tenancy_secrets.reset_cache()
