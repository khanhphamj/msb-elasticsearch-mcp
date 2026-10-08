"""Authenticate requests to the MCP server (Resource Server per the MCP Authorization / OAuth 2.1 spec).

Who calls the MCP server? In the AgentBase standard it is the **MCP Gateway** (connector outbound auth):

| Connector outbound auth | Gateway sends to server              | MCP_AUTH_MODE on server |
|-------------------------|--------------------------------------|-------------------------|
| API Key 2LO             | `Authorization: Bearer <api key>`    | api_key                 |
| OAuth 2LO (M2M)         | `Bearer <client access token>`       | jwt (or introspect)     |
| OAuth 3LO               | `Bearer <USER access token>`         | jwt — has user `sub`    |
| Inbound forward         | the same JWT agent/user sent to GW   | jwt (same IdP)          |
| No authorization        | —                                    | none (private net only) |

Set Header key = `Authorization`, Header value prefix = `Bearer ` when configuring the connector.

The server NEVER trusts a `user_id` tool parameter: end-user identity comes from the verified token
(`AccessToken.subject`) via `get_access_token()` — see server.py.
"""

from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache

import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier

from settings import Settings


class ApiKeyVerifier(TokenVerifier):
    """Static API key (Gateway outbound API Key 2LO). Env holds only the key's SHA-256."""

    def __init__(self, sha256_hashes: list[str], scopes: list[str]):
        self._hashes = [h.lower() for h in sha256_hashes]
        self._scopes = scopes

    async def verify_token(self, token: str) -> AccessToken | None:
        digest = hashlib.sha256(token.strip().encode()).hexdigest()
        if not any(hmac.compare_digest(digest, h) for h in self._hashes):
            return None
        # No end-user ⇒ subject=None: tools needing per-user data must refuse (see server.py)
        return AccessToken(token=token, client_id="api-key", scopes=self._scopes, subject=None)


@lru_cache(maxsize=4)
def _jwks(url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(url, cache_keys=True, lifespan=3600)


class JwtVerifier(TokenVerifier):
    """OAuth 2.0 access token as JWT (OIDC IdP: Keycloak, Auth0, Entra, Google...)."""

    def __init__(self, settings: Settings):
        self.s = settings

    async def verify_token(self, token: str) -> AccessToken | None:
        s = self.s
        try:
            key = _jwks(s.jwks_url).get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=s.jwt_algorithms,
                issuer=s.issuer or None,
                audience=s.audience or None,
                options={"require": ["exp"], "verify_aud": bool(s.audience)},
                leeway=30,
            )
        except jwt.PyJWTError:
            return None
        scope = claims.get("scope") or claims.get("scp") or []
        scopes = scope.split() if isinstance(scope, str) else list(scope)
        aud = claims.get("aud")
        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("client_id") or ""),
            scopes=scopes,
            expires_at=claims.get("exp"),
            resource=s.audience
            if s.audience and (aud == s.audience or s.audience in (aud or []))
            else None,
            subject=claims.get(s.user_claim),
        )


def build_verifier(settings: Settings) -> TokenVerifier | None:
    if settings.auth_mode == "api_key":
        return ApiKeyVerifier(settings.api_key_sha256, settings.required_scopes)
    if settings.auth_mode == "jwt":
        return JwtVerifier(settings)
    return None  # none: no auth, local dev only
