"""Authentication / authorization of the server itself (rarely changes when you add tools)."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import httpx
import pytest
from conftest import (
    API_KEY,
    API_KEY_ENV,
    ROOT,
    call,
    es_handler,
    free_port,
    list_tools,
    make_token,
    text,
)

LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
EMPTY_ES = {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}


def test_health_is_public(api_key_server):
    assert httpx.get(f"{api_key_server}/health").status_code == 200


def test_mcp_requires_auth(api_key_server):
    r = httpx.post(f"{api_key_server}/mcp", json=LIST)
    assert r.status_code == 401
    assert "resource_metadata" in r.headers.get("www-authenticate", "")  # RFC 9728 discovery


def test_wrong_api_key_rejected(api_key_server):
    r = httpx.post(f"{api_key_server}/mcp", headers={"Authorization": "Bearer nope"}, json=LIST)
    assert r.status_code == 401


async def test_api_key_lists_and_calls_tools(start_server):
    handler, calls = es_handler(lambda path, body: EMPTY_ES)
    base = start_server(API_KEY_ENV, backend=handler)
    names = [t.name for t in await list_tools(base, API_KEY)]
    assert {"get_overview", "search_logs", "get_metrics"} <= set(names)
    # The key carries the scopes listed in MCP_REQUIRED_SCOPES (logs.read + metrics.read)
    res = await call(base, API_KEY, "get_overview")
    assert not res.isError and len(calls) == 2


async def test_api_key_without_granted_scopes_cannot_call_scoped_tools(start_server):
    env = {k: v for k, v in API_KEY_ENV.items() if k != "MCP_REQUIRED_SCOPES"}
    base = start_server(env)
    res = await call(base, API_KEY, "search_logs", {"start": "now-1h"})
    assert res.isError and "logs.read" in text(res)


async def test_jwt_missing_scope(jwt_server):
    token = make_token("carol", scope="metrics.read")
    res = await call(jwt_server, token, "search_logs", {"start": "now-1h"})
    assert res.isError and "logs.read" in text(res)


@pytest.mark.parametrize(
    "override",
    [
        {"aud": "other-api"},  # token issued for another API of the same IdP
        {"iss": "https://evil.test"},
        {"exp": int(time.time()) - 3600},
    ],
    ids=["wrong-audience", "wrong-issuer", "expired"],
)
def test_jwt_invalid_tokens_rejected(jwt_server, override):
    r = httpx.post(
        f"{jwt_server}/mcp",
        headers={"Authorization": f"Bearer {make_token('carol', **override)}"},
        json=LIST,
    )
    assert r.status_code == 401


def test_metadata_endpoint(jwt_server):
    r = httpx.get(f"{jwt_server}/.well-known/oauth-protected-resource/mcp")
    if r.status_code == 404:
        r = httpx.get(f"{jwt_server}/.well-known/oauth-protected-resource")
    assert r.status_code == 200 and "https://idp.test" in r.text


def test_settings_defaults_are_local_and_none_is_blocked_elsewhere(monkeypatch):
    sys.modules.pop("settings", None)
    from settings import Settings

    s = Settings()
    assert (s.app_env, s.auth_mode) == ("local", "none")
    monkeypatch.setenv("MCP_APP_ENV", "dev")
    with pytest.raises(ValueError, match="only allowed"):
        Settings()


def test_settings_validate_elasticsearch_options(monkeypatch):
    sys.modules.pop("settings", None)
    from settings import Settings

    monkeypatch.setenv("MCP_BACKEND_USERNAME", "sre_agent")
    with pytest.raises(ValueError, match="together"):  # username without password
        Settings()
    monkeypatch.setenv("MCP_BACKEND_PASSWORD", "x")
    monkeypatch.setenv("MCP_BACKEND_TOKEN", "t")
    with pytest.raises(ValueError, match="not both"):
        Settings()
    monkeypatch.delenv("MCP_BACKEND_TOKEN")
    monkeypatch.setenv("MCP_LOGS_INDEX", "logs/../_all")  # would change the URL path
    with pytest.raises(ValueError, match="logs_index"):
        Settings()


def test_local_quickstart_real_process(tmp_path):
    """Exactly what the skill says: cp .env.example .env && python server.py, then call tools."""
    port = free_port()
    env_text = (ROOT / ".env.example").read_text().replace("8080", str(port))
    (tmp_path / ".env").write_text(env_text)
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCP_")}
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "server.py")],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        for _ in range(100):
            if proc.poll() is not None:
                pytest.fail(f"server crashed on startup:\n{proc.stdout.read()}")
            try:
                if httpx.get(f"http://127.0.0.1:{port}/health").status_code == 200:
                    break
            except httpx.ConnectError:
                time.sleep(0.1)
        else:
            pytest.fail("server did not become healthy")

        def cli(*args: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "call_tool.py"), *args],
                env={**env, "MCP_URL": f"http://127.0.0.1:{port}/mcp"},
                capture_output=True,
                text=True,
                timeout=30,
            )

        listed = cli()
        assert listed.returncode == 0 and "search_logs" in listed.stdout
        # .env.example has no Elasticsearch configured ⇒ a clean error, exit code 1
        res = cli("get_overview")
        assert res.returncode == 1 and "not configured" in res.stdout
    finally:
        proc.terminate()
        proc.communicate(timeout=10)  # also closes the stdout pipe
