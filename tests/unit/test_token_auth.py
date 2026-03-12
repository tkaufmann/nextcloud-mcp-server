"""Unit tests for token authentication (Bearer token layer)."""

import json
import os
from unittest.mock import patch

import pytest

from nextcloud_mcp_server.app import BasicAuthMiddleware
from nextcloud_mcp_server.config import parse_token_configs, resolve_token

# --- Token parsing tests ---


TOKEN_ENV = {
    "NEXTCLOUD_MCP_TOKEN_CLAUDE": "a" * 64,
    "NEXTCLOUD_MCP_TOKEN_CLAUDE_NC_USER": "tim",
    "NEXTCLOUD_MCP_TOKEN_CLAUDE_NC_PASSWORD": "app-pass-tim",
    "NEXTCLOUD_MCP_TOKEN_CLAUDE_SCOPES": "files:read,files:write,notes:read",
    "NEXTCLOUD_MCP_TOKEN_N8N": "b" * 64,
    "NEXTCLOUD_MCP_TOKEN_N8N_NC_USER": "tim",
    "NEXTCLOUD_MCP_TOKEN_N8N_NC_PASSWORD": "app-pass-n8n",
    # No _SCOPES → full access
}


@pytest.mark.unit
def test_parse_token_configs_valid():
    """Parse two valid token definitions from environment."""
    with patch.dict(os.environ, TOKEN_ENV, clear=False):
        configs = parse_token_configs()

    assert "CLAUDE" in configs
    assert "N8N" in configs

    claude = configs["CLAUDE"]
    assert claude.secret == "a" * 64
    assert claude.nc_user == "tim"
    assert claude.nc_password == "app-pass-tim"
    assert claude.scopes == ["files:read", "files:write", "notes:read"]

    n8n = configs["N8N"]
    assert n8n.secret == "b" * 64
    assert n8n.scopes == []  # No _SCOPES → no access (deny by default)


@pytest.mark.unit
def test_parse_token_configs_incomplete():
    """Skip tokens with missing required fields."""
    env = {
        "NEXTCLOUD_MCP_TOKEN_BROKEN": "c" * 64,
        # Missing _NC_USER and _NC_PASSWORD
    }
    with patch.dict(os.environ, env, clear=False):
        configs = parse_token_configs()

    assert "BROKEN" not in configs


@pytest.mark.unit
def test_parse_token_configs_empty_env():
    """Return empty dict when no token vars are set."""
    with patch.dict(os.environ, {}, clear=True):
        configs = parse_token_configs()

    assert configs == {}


# --- Token lookup tests ---


@pytest.mark.unit
def test_resolve_token_valid():
    """Find matching token config by secret."""
    with patch.dict(os.environ, TOKEN_ENV, clear=False):
        # Reset module cache
        import nextcloud_mcp_server.config as cfg

        cfg._token_configs = None
        try:
            result = resolve_token("a" * 64)
            assert result is not None
            assert result.name == "CLAUDE"
        finally:
            cfg._token_configs = None


@pytest.mark.unit
def test_resolve_token_invalid():
    """Return None for unknown secret."""
    with patch.dict(os.environ, TOKEN_ENV, clear=False):
        import nextcloud_mcp_server.config as cfg

        cfg._token_configs = None
        try:
            result = resolve_token("x" * 64)
            assert result is None
        finally:
            cfg._token_configs = None


# --- Middleware tests ---


class MockApp:
    """Mock ASGI app for testing middleware."""

    def __init__(self):
        self.called = False
        self.received_scope = None

    async def __call__(self, scope, receive, send):
        self.called = True
        self.received_scope = scope


class ResponseCapture:
    """Capture ASGI response messages."""

    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(message)


BEARER_TOKEN_ENV = {
    **TOKEN_ENV,
    # Ensure the module cache is fresh per test
}


@pytest.mark.unit
async def test_middleware_bearer_valid_token():
    """Valid Bearer token maps to NC credentials in scope state."""
    mock_app = MockApp()
    middleware = BasicAuthMiddleware(mock_app)

    scope = {
        "type": "http",
        "headers": [(b"authorization", f"Bearer {'b' * 64}".encode())],
    }

    import nextcloud_mcp_server.config as cfg

    with patch.dict(os.environ, TOKEN_ENV, clear=False):
        cfg._token_configs = None
        try:
            await middleware(scope, None, None)  # type: ignore[arg-type]
        finally:
            cfg._token_configs = None

    assert mock_app.called
    assert scope["state"]["basic_auth"]["username"] == "tim"
    assert scope["state"]["basic_auth"]["password"] == "app-pass-n8n"


@pytest.mark.unit
async def test_middleware_bearer_valid_token_with_scopes():
    """Valid Bearer token with scopes injects synthetic AccessToken."""
    mock_app = MockApp()
    middleware = BasicAuthMiddleware(mock_app)

    scope = {
        "type": "http",
        "headers": [(b"authorization", f"Bearer {'a' * 64}".encode())],
    }

    import nextcloud_mcp_server.config as cfg

    with patch.dict(os.environ, TOKEN_ENV, clear=False):
        cfg._token_configs = None
        try:
            await middleware(scope, None, None)  # type: ignore[arg-type]
        finally:
            cfg._token_configs = None

    assert mock_app.called
    assert scope["state"]["basic_auth"]["username"] == "tim"
    assert scope["state"]["basic_auth"]["password"] == "app-pass-tim"


@pytest.mark.unit
async def test_middleware_bearer_invalid_token():
    """Invalid Bearer token returns 401 without calling downstream app."""
    mock_app = MockApp()
    middleware = BasicAuthMiddleware(mock_app)
    capture = ResponseCapture()

    scope = {
        "type": "http",
        "headers": [(b"authorization", b"Bearer invalid_token_value")],
    }

    import nextcloud_mcp_server.config as cfg

    with patch.dict(os.environ, TOKEN_ENV, clear=False):
        cfg._token_configs = None
        try:
            await middleware(scope, None, capture)  # type: ignore[arg-type]
        finally:
            cfg._token_configs = None

    assert not mock_app.called
    assert capture.messages[0]["status"] == 401
    body = json.loads(capture.messages[1]["body"])
    assert body["error"] == "Invalid bearer token"


@pytest.mark.unit
async def test_middleware_basic_auth_still_works():
    """BasicAuth continues to work alongside Bearer tokens."""
    import base64

    mock_app = MockApp()
    middleware = BasicAuthMiddleware(mock_app)

    credentials = base64.b64encode(b"admin:secret").decode("utf-8")
    scope = {
        "type": "http",
        "headers": [(b"authorization", f"Basic {credentials}".encode())],
    }

    await middleware(scope, None, None)  # type: ignore[arg-type]

    assert mock_app.called
    assert scope["state"]["basic_auth"]["username"] == "admin"
    assert scope["state"]["basic_auth"]["password"] == "secret"
