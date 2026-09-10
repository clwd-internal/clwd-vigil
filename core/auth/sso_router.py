"""``POST /api/auth/sso/session`` — exchange an Entra session for a Vigil JWT.

Container Apps EasyAuth terminates OIDC in front of the app. This endpoint is
the bridge between the identity it establishes and Vigil's existing session
model: it validates the caller with the auth sidecar, JIT-provisions a ``User``
on first sign-in, maps Entra app roles onto Vigil's ``Role`` values, and issues
the same JWT cookies ``/api/auth/login`` issues.

Deliberately a new file, and deliberately *only* this. ``core/auth/auth_service.py``
is a large, frequently-changed upstream file; adding an OIDC path inside it
would produce a rebase conflict on every upstream auth change for the lifetime
of the fork. Everything here reuses upstream's public surface —
``AuthService.generate_jwt_token``, ``AuthService.create_user``,
``set_auth_cookies`` — and adds nothing to it.

The endpoint is mounted by ``services/api/discovery.py`` purely by existing
here. It appears in ``PUBLIC_API_PATHS`` because a caller who does not yet have
a Vigil cookie is exactly who needs it; it is not unauthenticated, it is
authenticated by the sidecar rather than by a Vigil cookie. See
``core/auth/sso_principal.py`` for why that check is not a header read.
"""

from __future__ import annotations

import logging
import secrets as pysecrets
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request, Response

from core.auth.auth_cookies import set_auth_cookies
from core.auth.sso_principal import (
    EntraPrincipal,
    SsoDisabled,
    SsoError,
    default_role_id,
    map_roles,
    resolve_principal,
    sso_enabled,
)
from core.routing import Auth, RouterMeta
from core.time import utcnow

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/auth/sso",
    tags=["auth", "sso"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "This is the endpoint that establishes a Vigil session, so it cannot "
        "require one. It authenticates the caller against the Container Apps "
        "auth sidecar's /.auth/me rather than against a Vigil cookie, and "
        "refuses every request when VIGIL_SSO_ENABLED is unset."
    ),
    enabled=sso_enabled,
)


def _resolve_role_id(principal: EntraPrincipal) -> str:
    role_id = map_roles(principal.roles)
    if role_id:
        return role_id
    fallback = default_role_id()
    if not fallback:
        # An operator who sets VIGIL_SSO_DEFAULT_ROLE="" has asked for
        # unmapped users to be refused outright rather than admitted as
        # viewers. Honour that.
        raise SsoError(
            f"no Vigil role maps from Entra app roles {principal.roles!r} and "
            "no default role is configured"
        )
    logger.warning(
        "SSO user %s has no mapped Entra app role (roles=%r); assigning %s",
        principal.email,
        principal.roles,
        fallback,
    )
    return fallback


def _provision(principal: EntraPrincipal, role_id: str) -> Dict[str, Any]:
    """Find or create the local user for an Entra principal.

    Matching is on email, which is the only stable identifier shared between
    Entra and upstream's user table. The Entra object id would be better —
    email addresses are reassignable — but storing it needs a schema change,
    and a schema change here would be a change to an upstream migration file.
    Recorded as a known limitation in docs/UPSTREAM.md.
    """
    from core.auth.auth_service import AuthService
    from core.storage.models import User
    from core.storage.unit_of_work import unit_of_work

    with unit_of_work() as session:
        user = (
            session.query(User)
            .filter(
                (User.email == principal.email)
                | (User.username == principal.username)
            )
            .first()
        )

        if user is None:
            # The password is random and never returned to anyone. It exists
            # because password_hash is NOT NULL; an SSO user has no local
            # password and must not be able to authenticate with one, so a
            # 64-character random value that is discarded immediately is the
            # correct thing to store rather than a fixed sentinel.
            user = AuthService.create_user(
                username=principal.username,
                email=principal.email,
                password=pysecrets.token_urlsafe(48),
                full_name=principal.display_name or principal.email,
                role_id=role_id,
                session=session,
            )
            if user is None:
                raise SsoError("could not provision a local user for this principal")
            created = True
        else:
            created = False
            if not user.is_active:
                # Deactivation in Vigil is an explicit administrative act and
                # must outrank a valid Entra session.
                raise SsoError(f"user {principal.email} is deactivated")
            # Role changes in Entra take effect at next sign-in. Not doing this
            # would mean revoking someone's admin role in Entra leaves them an
            # admin in Vigil indefinitely.
            if user.role_id != role_id:
                logger.info(
                    "SSO role change for %s: %s -> %s",
                    principal.email,
                    user.role_id,
                    role_id,
                )
                user.role_id = role_id
            if principal.display_name and user.full_name != principal.display_name:
                user.full_name = principal.display_name

        user.last_login = utcnow()
        user.login_count = (user.login_count or 0) + 1
        user.failed_login_count = 0
        session.flush()

        # Tokens are generated inside the unit of work so the User is still
        # attached; reading user.role_id after the session closes would raise.
        access = AuthService.generate_jwt_token(user, token_type="access")
        refresh = AuthService.generate_jwt_token(user, token_type="refresh")

        return {
            "created": created,
            "access_token": access,
            "refresh_token": refresh,
            "user": {
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "role_id": user.role_id,
            },
        }


@router.post("/session")
async def create_sso_session(request: Request, response: Response) -> Dict[str, Any]:
    """Establish a Vigil session from the Entra identity the sidecar asserts."""
    try:
        principal = await resolve_principal(dict(request.headers))
    except SsoDisabled:
        # 404, not 401: an unconfigured feature should look absent, not like a
        # rejected credential. (Belt and braces — ROUTER_META.enabled already
        # keeps this router unmounted when SSO is off.)
        raise HTTPException(status_code=404, detail="SSO is not enabled")
    except SsoError as e:
        logger.warning("SSO session rejected: %s", e)
        raise HTTPException(status_code=401, detail="SSO authentication failed") from e

    try:
        role_id = _resolve_role_id(principal)
        result = _provision(principal, role_id)
    except SsoError as e:
        logger.warning("SSO provisioning rejected for %s: %s", principal.email, e)
        raise HTTPException(status_code=403, detail=str(e)) from e
    except Exception as e:
        logger.error("SSO provisioning failed for %s: %s", principal.email, e)
        raise HTTPException(status_code=500, detail="SSO provisioning failed") from e

    set_auth_cookies(response, result["access_token"], result["refresh_token"])

    logger.info(
        "SSO session established for %s (role=%s, provisioned=%s, idp=%s)",
        principal.email,
        role_id,
        result["created"],
        principal.identity_provider or "entra",
    )

    # The tokens themselves are not in the body: they are in HttpOnly cookies,
    # and returning them as well would put them somewhere JavaScript can read.
    return {
        "authenticated": True,
        "provisioned": result["created"],
        "user": result["user"],
        "entra_roles": principal.roles,
    }


@router.get("/status")
async def sso_status(request: Request) -> Dict[str, Any]:
    """Whether SSO is on, and whether this request carries an Entra session.

    Lets the frontend decide between showing a password form and redirecting
    to the sidecar's sign-in, without a failed POST first. Reports state only —
    no claims, no roles, no endpoint URL.
    """
    principal: Optional[EntraPrincipal] = None
    try:
        principal = await resolve_principal(dict(request.headers))
    except SsoError:
        pass
    return {
        "enabled": sso_enabled(),
        "authenticated": principal is not None,
    }
