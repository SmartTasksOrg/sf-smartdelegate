"""Reference IdentitySource: a static JWKS, the engine's own ID-token
verification, and the claim rules of sf_smartdelegate.bridges.claims.

It is the same check the engine makes when `idp` is configured and
`issue_token` is called with `id_token` (spec/API.md). Use this class when
your token service wants the identity itself, for example to choose the role,
before it calls `issue_token(user=..., groups=...)` with the admin key.
"""
from __future__ import annotations

import time

from sf_smartdelegate.bridges import BridgeError
from sf_smartdelegate.bridges.claims import groups_from_claims
from sf_smartdelegate.errors import EngineError
from sf_smartdelegate.tokens import verify_id_token

from ..contracts import Identity, IdentityError


class JwksIdentitySource:
    def __init__(self, issuer: str, audience: str, jwks: dict, *, groups_claim: str | None = "groups", group_map: dict | None = None,
                 user_claim: str = "sub", rule: dict | None = None, clock=time.time):
        """`rule`: a sf_smartdelegate.bridges.claims rule (provider presets for
        Entra, Okta, Keycloak, Cognito, Auth0, Google). Default: the generic
        rule over `groups_claim` with `group_map`. With neither a claim nor a
        rule the identity has no groups and membership comes from the
        directory sync alone."""
        if not issuer or not audience or not isinstance(jwks, dict) or not jwks.get("keys"):
            raise IdentityError("invalid_config", "issuer, audience and a JWKS with at least one key are required")
        self.issuer, self.audience, self.jwks, self.user_claim, self.clock = issuer, audience, jwks, user_claim, clock
        self.rule = rule or ({"provider": "generic", "claim": groups_claim, **({"map": group_map} if group_map is not None else {})}
                             if groups_claim else None)

    def verify(self, id_token: str) -> dict:
        """The claims of a token that verifies; IdentityError otherwise."""
        if not isinstance(id_token, str) or not id_token:
            raise IdentityError("id_token_invalid", "no ID token")
        try:
            return verify_id_token(id_token, self.jwks, self.issuer, self.audience, int(self.clock()))
        except EngineError as e:
            raise IdentityError(e.code, e.message) from None

    def groups(self, claims: dict) -> list:
        try:
            return groups_from_claims(claims, self.rule) if self.rule else []
        except BridgeError as e:       # malformed claim, or an overage: never read as "no groups"
            raise IdentityError(e.code, e.message) from None

    def identify(self, id_token: str) -> Identity:
        claims = self.verify(id_token)
        user = claims.get(self.user_claim)
        if not isinstance(user, str) or not user:
            raise IdentityError("id_token_invalid", f"the ID token has no '{self.user_claim}' claim")
        return Identity(user, self.groups(claims), self.issuer, claims["exp"])
