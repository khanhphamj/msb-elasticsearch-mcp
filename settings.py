from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Index name / alias / wildcard: it becomes part of a URL path, so keep it to a safe alphabet.
INDEX_PATTERN = r"^[A-Za-z0-9._*,-]{1,200}$"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", env_prefix="MCP_", env_ignore_empty=True
    )

    app_env: Literal["local", "dev", "staging", "prod"] = "local"
    server_name: str = "sre-es"
    # Public URL of the MCP endpoint (resource identifier, RFC 9728/8707), e.g.
    # https://endpoint-<id>.agentbase-runtime.aiplatform.vngcloud.vn/mcp
    resource_url: str = "http://localhost:8080/mcp"
    port: int = 8080  # AgentBase Runtime expects 8080

    # api_key (Gateway outbound API Key) | jwt (OAuth 2LO/3LO, inbound forward) | none (local only)
    auth_mode: Literal["api_key", "jwt", "none"] = "none"
    api_key_sha256: list[str] = Field(default_factory=list)
    issuer: str = ""  # OAuth authorization server (iss) — required for jwt
    jwks_url: str = ""
    audience: str = ""  # should = resource_url or the API identifier registered at the IdP
    user_claim: str = "sub"
    jwt_algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    # Applied to every request. In api_key mode these are also the scopes GRANTED to the key
    # (tools check `logs.read` / `metrics.read` via require_scope()).
    required_scopes: list[str] = Field(default_factory=list)

    # Elasticsearch behind the tools (see backend.py). Use a READ-ONLY user limited to the two indices.
    backend_url: str = ""  # e.g. http://127.0.0.1:9200 ; empty ⇒ tools answer "not configured"
    backend_username: str = ""
    backend_password: str = ""
    backend_token: str = ""  # alternative to username/password, sent as `Bearer`
    backend_timeout_s: float = 10.0
    logs_index: str = Field(default="logs-sample", pattern=INDEX_PATTERN)
    metrics_index: str = Field(default="metrics-sample", pattern=INDEX_PATTERN)

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        if self.auth_mode == "none" and self.app_env != "local":
            raise ValueError("MCP_AUTH_MODE=none is only allowed when MCP_APP_ENV=local")
        if self.auth_mode == "api_key" and not self.api_key_sha256:
            raise ValueError(
                "MCP_AUTH_MODE=api_key requires MCP_API_KEY_SHA256 (JSON list of SHA-256 hex)"
            )
        if self.auth_mode == "jwt" and not (self.jwks_url and self.issuer):
            raise ValueError("MCP_AUTH_MODE=jwt requires MCP_JWKS_URL and MCP_ISSUER")
        if bool(self.backend_username) != bool(self.backend_password):
            raise ValueError("MCP_BACKEND_USERNAME and MCP_BACKEND_PASSWORD must be set together")
        if self.backend_token and self.backend_username:
            raise ValueError("Use MCP_BACKEND_TOKEN or MCP_BACKEND_USERNAME/PASSWORD, not both")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
