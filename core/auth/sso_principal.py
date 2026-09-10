"""Validating an Entra principal forwarded by Container Apps EasyAuth.

Container Apps' built-in authentication runs as a sidecar in front of the app.
It terminates OIDC against Entra ID and forwards the signed-in identity to the
container as a base64 JSON blob in ``X-MS-CLIENT-PRINCIPAL``.

**The header is not evidence.** It is an ordinary request header. If the
container is ever reachable without traversing the sidecar — a misconfigured
ingress, a network policy that allows direct pod access, a future revision that
turns EasyAuth off, an internal service with a route to the app — then anyone
who can set that header becomes any user they name, including an administrator.
Base64 is not a signature. Decoding the header and believing it is a complete
authentication bypass, and the only thing standing between the two is this
module.

So the header is used only as a hint that a request *claims* to be
authenticated. The identity is then read back from the sidecar's own
``/.auth/me`` endpoint, which is served by the sidecar process itself and can
only answer for a session the sidecar established. The incoming cookies and
headers are forwarded so the sidecar resolves the caller's session rather than
some other one; a caller who forged the header has no such session and gets an
empty array back.

``VIGIL_SSO_PRINCIPAL_ENDPOINT`` (default ``/.auth/me``) is where to ask.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

PRINCIPAL_HEADER = "x-ms-client-principal"
PRINCIPAL_NAME_HEADER = "x-ms-client-principal-name"
PRINCIPAL_ID_HEADER = "x-ms-client-principal-id"

DEFAULT_PRINCIPAL_ENDPOINT = "/.auth/me"
DEFAULT_SIDECAR_BASE = "http://127.0.0.1"

#: Claim types Entra emits for the pieces we need. Entra is inconsistent about
#: which it sends depending on token version and app configuration, so each
#: field has several candidates rather than one.
_EMAIL_CLAIMS = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "preferred_username",
    "email",
    "upn",
    "unique_name",
)
_NAME_CLAIMS = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "name",
)
_OID_CLAIMS = (
    "http://schemas.microsoft.com/identity/claims/objectidentifier",
    "oid",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
    "sub",
)
_ROLE_CLAIMS = (
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
    "roles",
    "role",
)


class SsoError(Exception):
    """SSO could not establish an identity. Always a 401 to the caller."""


class SsoDisabled(SsoError):
    """VIGIL_SSO_ENABLED is not set. Separate so the router can 404 rather
    than 401: an unconfigured feature should not look like a bad credential."""


@dataclass
class EntraPrincipal:
    object_id: str
    email: str
    display_name: str = ""
    roles: List[str] = field(default_factory=list)
    identity_provider: str = ""
    raw_claims: Dict[str, Any] = field(default_factory=dict)

    @property
    def username(self) -> str:
        """Local username. The email local part is not unique across domains
        in a multi-customer deployment, so the full address is the username."""
        return self.email.lower()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def sso_enabled() -> bool:
    """Read at call time, not import time.

    ``Settings`` uses ``extra="ignore"``, so a new field there would be an edit
    to an upstream hot file for no benefit, and tests that flip the env var
    should take effect without a reimport.
    """
    raw = os.environ.get("VIGIL_SSO_ENABLED") or ""  # noqa: ENV001
    return raw.strip().lower() in ("1", "true", "yes", "on")


def principal_endpoint() -> str:
    """Absolute URL of the sidecar's ``/.auth/me``.

    A bare path is resolved against the sidecar on localhost, because that is
    where Container Apps' auth sidecar listens — it shares the pod's network
    namespace. Requiring a full URL would be one more thing for the
    infrastructure to get wrong.
    """
    configured = os.environ.get("VIGIL_SSO_PRINCIPAL_ENDPOINT")  # noqa: ENV001
    raw = (configured or DEFAULT_PRINCIPAL_ENDPOINT).strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    sidecar = os.environ.get("VIGIL_SSO_SIDECAR_BASE")  # noqa: ENV001
    base = (sidecar or DEFAULT_SIDECAR_BASE).rstrip("/")
    if not raw.startswith("/"):
        raw = "/" + raw
    return f"{base}{raw}"


def default_role_id() -> str:
    """Role for a user whose Entra app roles map to nothing we recognise.

    Viewer, deliberately. An unmapped role is a configuration gap, and the safe
    reading of a configuration gap is "least privilege", not "analyst". Set
    ``VIGIL_SSO_DEFAULT_ROLE=""`` to reject such users outright instead.
    """
    if "VIGIL_SSO_DEFAULT_ROLE" in os.environ:  # noqa: ENV001
        return (os.environ.get("VIGIL_SSO_DEFAULT_ROLE") or "").strip()  # noqa: ENV001
    return "role-viewer"


def role_map() -> Dict[str, str]:
    """Entra app role value -> Vigil role_id.

    The defaults use the Entra app role values the infrastructure provisions.
    ``VIGIL_SSO_ROLE_MAP`` overrides, as JSON, for a customer whose Entra app
    registration names its roles differently.
    """
    defaults = {
        "admin": "role-admin",
        "vigil.admin": "role-admin",
        "senioranalyst": "role-senior-analyst",
        "senior_analyst": "role-senior-analyst",
        "senior-analyst": "role-senior-analyst",
        "vigil.senioranalyst": "role-senior-analyst",
        "analyst": "role-analyst",
        "vigil.analyst": "role-analyst",
        "viewer": "role-viewer",
        "vigil.viewer": "role-viewer",
        "reader": "role-viewer",
    }
    raw = (os.environ.get("VIGIL_SSO_ROLE_MAP") or "").strip()  # noqa: ENV001
    if not raw:
        return defaults
    try:
        override = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("VIGIL_SSO_ROLE_MAP is not valid JSON, using defaults: %s", e)
        return defaults
    if not isinstance(override, dict):
        logger.error("VIGIL_SSO_ROLE_MAP must be a JSON object, using defaults")
        return defaults
    defaults.update({str(k).strip().lower(): str(v) for k, v in override.items()})
    return defaults


#: Most privileged first. A user in several Entra app roles gets the strongest,
#: which is what an operator means by granting both "analyst" and "admin".
_ROLE_PRECEDENCE = (
    "role-admin",
    "role-senior-analyst",
    "role-analyst",
    "role-viewer",
)


def map_roles(entra_roles: List[str]) -> Optional[str]:
    """Vigil role_id for a set of Entra app roles, or None if none map."""
    mapping = role_map()
    matched = {
        mapping[str(role).strip().lower()]
        for role in entra_roles or []
        if str(role).strip().lower() in mapping
    }
    for role_id in _ROLE_PRECEDENCE:
        if role_id in matched:
            return role_id
    return next(iter(matched), None)


# ---------------------------------------------------------------------------
# Claim extraction
# ---------------------------------------------------------------------------


def _claims_to_dict(claims: Any) -> Dict[str, List[str]]:
    """``/.auth/me`` returns ``[{"typ": ..., "val": ...}]``; the header returns
    ``{"claims": [{"typ": ..., "val": ...}]}``. Same shape, both multi-valued
    (``roles`` in particular repeats)."""
    out: Dict[str, List[str]] = {}
    for claim in claims or []:
        if not isinstance(claim, dict):
            continue
        typ = claim.get("typ") or claim.get("type")
        val = claim.get("val") or claim.get("value")
        if typ is None or val is None:
            continue
        out.setdefault(str(typ), []).append(str(val))
    return out


def _first(claims: Dict[str, List[str]], names) -> str:
    for name in names:
        values = claims.get(name)
        if values:
            return values[0]
    return ""


def principal_from_payload(payload: Any) -> EntraPrincipal:
    """Build a principal from one ``/.auth/me`` entry or a decoded header.

    Raises :class:`SsoError` when the payload carries no usable identity —
    a principal with no object id and no email is not something to guess at.
    """
    if isinstance(payload, list):
        payload = payload[0] if payload else {}
    if not isinstance(payload, dict):
        raise SsoError("principal payload is not an object")

    raw_claims = payload.get("claims") or payload.get("user_claims") or []
    claims = _claims_to_dict(raw_claims)

    email = _first(claims, _EMAIL_CLAIMS)
    if not email:
        # /.auth/me puts the IdP's own name for the user here; the header
        # equivalent is userDetails.
        email = str(payload.get("user_id") or payload.get("userDetails") or "").strip()

    object_id = _first(claims, _OID_CLAIMS) or str(payload.get("userId") or "").strip()

    roles: List[str] = []
    for name in _ROLE_CLAIMS:
        roles.extend(claims.get(name, []))
    # The header form nests roles rather than emitting role claims.
    for key in ("userRoles", "roles"):
        value = payload.get(key)
        if isinstance(value, list):
            roles.extend(str(v) for v in value)

    if not email and not object_id:
        raise SsoError(
            "principal carries neither an email nor an object id; refusing to "
            "provision a user from it"
        )

    return EntraPrincipal(
        object_id=object_id or email,
        email=(email or f"{object_id}@entra.invalid").lower(),
        display_name=_first(claims, _NAME_CLAIMS)
        or str(payload.get("userDetails") or ""),
        # De-duplicated but order-preserving: role precedence is decided in
        # map_roles, not by whichever claim happened to arrive first.
        roles=list(dict.fromkeys(r for r in roles if r)),
        identity_provider=str(
            payload.get("provider_name") or payload.get("identityProvider") or ""
        ),
        raw_claims=payload,
    )


def decode_client_principal_header(value: str) -> Dict[str, Any]:
    """Decode ``X-MS-CLIENT-PRINCIPAL``.

    Used for logging and for the strictly-optional consistency check in
    :func:`resolve_principal`. Never as the authentication decision: see this
    module's docstring for why.
    """
    try:
        padded = value + "=" * (-len(value) % 4)
        return json.loads(base64.b64decode(padded).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
        raise SsoError(f"X-MS-CLIENT-PRINCIPAL is not decodable: {e}") from e


# ---------------------------------------------------------------------------
# The actual check
# ---------------------------------------------------------------------------

_FORWARDED_HEADERS = (
    "cookie",
    "authorization",
    PRINCIPAL_HEADER,
    "x-ms-client-principal-idp",
    "x-ms-token-aad-id-token",
    "x-zumo-auth",
)


async def fetch_principal(request_headers: Dict[str, str]) -> EntraPrincipal:
    """Ask the auth sidecar who the caller is.

    The caller's own credentials are forwarded so the sidecar resolves *this*
    session. A forged ``X-MS-CLIENT-PRINCIPAL`` with no accompanying session
    cookie produces an empty ``/.auth/me`` response, which is the rejection.
    """
    url = principal_endpoint()
    lowered = {k.lower(): v for k, v in request_headers.items()}
    forwarded = {h: lowered[h] for h in _FORWARDED_HEADERS if h in lowered}

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            resp = await client.get(url, headers=forwarded)
    except httpx.HTTPError as e:
        # Fail closed. An unreachable sidecar means we cannot tell who the
        # caller is, and "cannot tell" must never resolve to "let them in".
        raise SsoError(f"auth sidecar at {url} is unreachable: {e}") from e

    if resp.status_code == 401 or resp.status_code == 403:
        raise SsoError("auth sidecar reports no authenticated session")
    if resp.status_code >= 400:
        raise SsoError(f"auth sidecar returned HTTP {resp.status_code}")

    try:
        payload = resp.json()
    except ValueError as e:
        # A redirect to a login page or an HTML error page lands here. It is
        # not an identity, so it is a rejection.
        raise SsoError(f"auth sidecar response is not JSON: {e}") from e

    if isinstance(payload, list) and not payload:
        raise SsoError("auth sidecar reports no authenticated session")
    if isinstance(payload, dict) and payload.get("clientPrincipal") is not None:
        payload = payload["clientPrincipal"]
    if not payload:
        raise SsoError("auth sidecar reports no authenticated session")

    return principal_from_payload(payload)


async def resolve_principal(request_headers: Dict[str, str]) -> EntraPrincipal:
    """The one entry point a caller should use.

    Order matters: the sidecar is consulted first and its answer is
    authoritative. The header is compared afterwards only to detect a
    mismatch, which means someone is presenting a principal that is not the
    one their session establishes — worth a loud log even though the sidecar's
    answer is the one that wins.
    """
    if not sso_enabled():
        raise SsoDisabled("VIGIL_SSO_ENABLED is not set")

    principal = await fetch_principal(request_headers)

    lowered = {k.lower(): v for k, v in request_headers.items()}
    header_value = lowered.get(PRINCIPAL_HEADER)
    if header_value:
        try:
            claimed = principal_from_payload(
                decode_client_principal_header(header_value)
            )
        except SsoError:
            logger.warning("X-MS-CLIENT-PRINCIPAL present but undecodable; ignoring it")
        else:
            if claimed.email and claimed.email != principal.email:
                logger.error(
                    "SSO principal mismatch: header claims %s, auth sidecar says "
                    "%s. Using the sidecar. This is what a spoofing attempt "
                    "looks like.",
                    claimed.email,
                    principal.email,
                )
    return principal
