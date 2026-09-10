"""The Entra SSO bridge, and the authentication bypass it exists to prevent.

Container Apps EasyAuth forwards the signed-in identity as a base64 JSON blob
in ``X-MS-CLIENT-PRINCIPAL``. That header is not evidence: it is an ordinary
request header, base64 is not a signature, and if the container is ever
reachable without traversing the auth sidecar then anyone who can set it
becomes any user they name — including an administrator.

The mitigation is that the identity is read back from the sidecar's own
``/.auth/me``, which can only answer for a session the sidecar established.
The first test in this file is the one that matters: a forged header, with no
sidecar-backed session, must be rejected.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import httpx
import pytest
import respx

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.auth import sso_principal as sso  # noqa: E402

pytestmark = pytest.mark.unit

AUTH_ME = "http://127.0.0.1/.auth/me"


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("VIGIL_SSO_ENABLED", "true")
    monkeypatch.delenv("VIGIL_SSO_PRINCIPAL_ENDPOINT", raising=False)
    monkeypatch.delenv("VIGIL_SSO_SIDECAR_BASE", raising=False)
    monkeypatch.delenv("VIGIL_SSO_ROLE_MAP", raising=False)
    monkeypatch.delenv("VIGIL_SSO_DEFAULT_ROLE", raising=False)


def _claims(email="jane@contoso.test", roles=("Analyst",), name="Jane Doe", oid="oid-1"):
    claims = [
        {"typ": "preferred_username", "val": email},
        {"typ": "name", "val": name},
        {"typ": "http://schemas.microsoft.com/identity/claims/objectidentifier", "val": oid},
    ]
    claims += [
        {"typ": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "val": r}
        for r in roles
    ]
    return claims


def _auth_me_body(**kw):
    return [{"provider_name": "aad", "user_id": kw.get("email", "jane@contoso.test"),
             "user_claims": _claims(**kw)}]


def _forged_header(email="attacker@evil.test", roles=("Admin",)):
    payload = {
        "auth_typ": "aad",
        "claims": _claims(email=email, roles=roles, name="Mallory", oid="oid-evil"),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


# ---------------------------------------------------------------------------
# The bypass
# ---------------------------------------------------------------------------


@respx.mock
async def test_a_forged_client_principal_header_alone_is_rejected():
    """THE test. A caller who sets X-MS-CLIENT-PRINCIPAL but has no session
    with the auth sidecar must not be authenticated as anyone, least of all as
    the administrator the header names.

    The sidecar answers [] — it has no session for this caller — and that is
    the rejection. If this test ever starts passing a principal through, the
    deployment has an authentication bypass to administrator.
    """
    respx.get(AUTH_ME).mock(return_value=httpx.Response(200, json=[]))

    with pytest.raises(sso.SsoError):
        await sso.resolve_principal({"X-MS-CLIENT-PRINCIPAL": _forged_header()})


@respx.mock
async def test_a_forged_header_is_ignored_when_the_sidecar_names_someone_else():
    """A valid low-privilege session plus a forged admin header must yield the
    low-privilege identity, not the claimed one."""
    respx.get(AUTH_ME).mock(
        return_value=httpx.Response(200, json=_auth_me_body(roles=("Viewer",)))
    )

    principal = await sso.resolve_principal(
        {"X-MS-CLIENT-PRINCIPAL": _forged_header(email="admin@contoso.test")}
    )
    assert principal.email == "jane@contoso.test"
    assert principal.roles == ["Viewer"]


@respx.mock
async def test_an_unreachable_sidecar_fails_closed():
    """"Cannot tell who the caller is" must never resolve to "let them in"."""
    respx.get(AUTH_ME).mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(sso.SsoError):
        await sso.resolve_principal({"X-MS-CLIENT-PRINCIPAL": _forged_header()})


@respx.mock
@pytest.mark.parametrize("status", [401, 403, 500, 302])
async def test_a_non_ok_sidecar_response_is_a_rejection(status):
    respx.get(AUTH_ME).mock(return_value=httpx.Response(status, json={}))
    with pytest.raises(sso.SsoError):
        await sso.resolve_principal({})


@respx.mock
async def test_a_login_page_instead_of_json_is_a_rejection():
    """An unauthenticated caller often gets HTML back, not a 401."""
    respx.get(AUTH_ME).mock(
        return_value=httpx.Response(200, text="<html>Sign in</html>")
    )
    with pytest.raises(sso.SsoError):
        await sso.resolve_principal({})


async def test_sso_disabled_refuses_before_any_network_call(monkeypatch):
    monkeypatch.delenv("VIGIL_SSO_ENABLED", raising=False)
    # No respx mock: any HTTP call here would raise a different error, so this
    # also proves the disabled check comes first.
    with pytest.raises(sso.SsoDisabled):
        await sso.resolve_principal({"X-MS-CLIENT-PRINCIPAL": _forged_header()})


@respx.mock
async def test_the_callers_own_credentials_are_forwarded_to_the_sidecar():
    """The sidecar has to resolve *this* caller's session. Without forwarding
    the session cookie it would answer for nobody, or worse, for whoever the
    app itself last authenticated as."""
    route = respx.get(AUTH_ME).mock(
        return_value=httpx.Response(200, json=_auth_me_body())
    )
    await sso.resolve_principal(
        {
            "Cookie": "AppServiceAuthSession=abc",
            "X-MS-CLIENT-PRINCIPAL": _forged_header(email="jane@contoso.test"),
            "X-Unrelated": "should-not-be-forwarded",
        }
    )
    sent = route.calls.last.request.headers
    assert sent["cookie"] == "AppServiceAuthSession=abc"
    assert "x-unrelated" not in sent


# ---------------------------------------------------------------------------
# Endpoint resolution
# ---------------------------------------------------------------------------


def test_the_principal_endpoint_defaults_to_the_sidecar_on_localhost():
    assert sso.principal_endpoint() == "http://127.0.0.1/.auth/me"


def test_a_bare_path_is_resolved_against_the_sidecar(monkeypatch):
    monkeypatch.setenv("VIGIL_SSO_PRINCIPAL_ENDPOINT", "auth/whoami")
    assert sso.principal_endpoint() == "http://127.0.0.1/auth/whoami"


def test_an_absolute_endpoint_is_used_verbatim(monkeypatch):
    monkeypatch.setenv("VIGIL_SSO_PRINCIPAL_ENDPOINT", "https://side.car/.auth/me")
    assert sso.principal_endpoint() == "https://side.car/.auth/me"


# ---------------------------------------------------------------------------
# Claim extraction
# ---------------------------------------------------------------------------


@respx.mock
async def test_claims_are_read_from_the_sidecar_payload():
    respx.get(AUTH_ME).mock(return_value=httpx.Response(200, json=_auth_me_body()))
    principal = await sso.resolve_principal({})
    assert principal.email == "jane@contoso.test"
    assert principal.display_name == "Jane Doe"
    assert principal.object_id == "oid-1"
    assert principal.roles == ["Analyst"]
    assert principal.identity_provider == "aad"


def test_the_static_web_apps_client_principal_shape_is_also_understood():
    """Some fronting configurations return {"clientPrincipal": {...}} with
    userRoles rather than role claims."""
    principal = sso.principal_from_payload(
        {
            "userId": "abc",
            "userDetails": "bob@contoso.test",
            "identityProvider": "aad",
            "userRoles": ["Viewer", "authenticated"],
        }
    )
    assert principal.email == "bob@contoso.test"
    assert "Viewer" in principal.roles


def test_a_principal_with_no_identity_at_all_is_refused():
    with pytest.raises(sso.SsoError):
        sso.principal_from_payload({"provider_name": "aad", "user_claims": []})


def test_an_undecodable_header_raises_rather_than_yielding_a_blank_principal():
    with pytest.raises(sso.SsoError):
        sso.decode_client_principal_header("not base64 at all !!!")
    with pytest.raises(sso.SsoError):
        sso.decode_client_principal_header(base64.b64encode(b"not json").decode())


def test_duplicate_roles_collapse_but_order_is_preserved():
    principal = sso.principal_from_payload(
        {"claims": _claims(roles=("Analyst", "Admin", "Analyst"))}
    )
    assert principal.roles == ["Analyst", "Admin"]


def test_the_username_is_the_full_email_not_the_local_part():
    """jane@contoso.test and jane@fabrikam.test are different people, and
    username is UNIQUE in the users table."""
    principal = sso.principal_from_payload({"claims": _claims(email="Jane@Contoso.test")})
    assert principal.username == "jane@contoso.test"


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entra_roles,expected",
    [
        (["Admin"], "role-admin"),
        (["Analyst"], "role-analyst"),
        (["SeniorAnalyst"], "role-senior-analyst"),
        (["Viewer"], "role-viewer"),
        (["vigil.admin"], "role-admin"),
        (["ANALYST"], "role-analyst"),
        ([], None),
        (["SomethingElse"], None),
    ],
)
def test_entra_app_roles_map_onto_vigil_roles(entra_roles, expected):
    assert sso.map_roles(entra_roles) == expected


def test_the_most_privileged_matching_role_wins():
    """Granting someone both Analyst and Admin in Entra means Admin. Picking
    whichever claim arrived first would make the result depend on Entra's
    claim ordering."""
    assert sso.map_roles(["Analyst", "Admin", "Viewer"]) == "role-admin"
    assert sso.map_roles(["Viewer", "Analyst"]) == "role-analyst"


def test_the_role_map_is_overridable_for_a_differently_named_app_registration(
    monkeypatch,
):
    monkeypatch.setenv("VIGIL_SSO_ROLE_MAP", json.dumps({"SOC.Tier3": "role-admin"}))
    assert sso.map_roles(["SOC.Tier3"]) == "role-admin"
    # The defaults survive the override rather than being replaced by it.
    assert sso.map_roles(["Viewer"]) == "role-viewer"


def test_a_malformed_role_map_falls_back_to_the_defaults_rather_than_failing_open(
    monkeypatch,
):
    monkeypatch.setenv("VIGIL_SSO_ROLE_MAP", "{not json")
    assert sso.map_roles(["Admin"]) == "role-admin"
    monkeypatch.setenv("VIGIL_SSO_ROLE_MAP", '["a", "b"]')
    assert sso.map_roles(["Admin"]) == "role-admin"


def test_the_default_role_for_an_unmapped_user_is_least_privilege():
    """An unmapped Entra role is a configuration gap. The safe reading of a
    configuration gap is viewer, never analyst and certainly never admin."""
    assert sso.default_role_id() == "role-viewer"


def test_an_operator_can_refuse_unmapped_users_outright(monkeypatch):
    monkeypatch.setenv("VIGIL_SSO_DEFAULT_ROLE", "")
    assert sso.default_role_id() == ""


# ---------------------------------------------------------------------------
# Router wiring
# ---------------------------------------------------------------------------


def test_the_router_is_not_mounted_when_sso_is_disabled(monkeypatch):
    """ROUTER_META.enabled is evaluated at mount time, so an off deployment
    does not expose the endpoint at all."""
    from core.auth import sso_router

    monkeypatch.setenv("VIGIL_SSO_ENABLED", "true")
    assert sso_router.ROUTER_META.enabled() is True
    monkeypatch.setenv("VIGIL_SSO_ENABLED", "false")
    assert sso_router.ROUTER_META.enabled() is False


def test_the_sso_paths_are_declared_public_so_the_route_audit_stays_honest():
    """They are not unauthenticated — they are authenticated by the sidecar
    rather than by a Vigil cookie — but the route-inventory test needs them
    named explicitly rather than silently exempt."""
    from services.api.main import PUBLIC_API_PATHS

    assert "/api/auth/sso/session" in PUBLIC_API_PATHS
    assert "/api/health/ready" in PUBLIC_API_PATHS
