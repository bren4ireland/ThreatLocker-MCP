"""Tests for the ThreatLocker HTTP client (mocked, no live API calls)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("THREATLOCKER_API_KEY", "test-key")
os.environ.setdefault("THREATLOCKER_ORG_ID", "00000000-0000-0000-0000-000000000000")
os.environ.setdefault("THREATLOCKER_BASE_URL", "https://api.example.test")

from threatlocker_mcp.client import ThreatLockerAPIError, ThreatLockerClient  # noqa: E402
from threatlocker_mcp.config import Config  # noqa: E402


@pytest.fixture
def config() -> Config:
    return Config(
        api_key=os.environ["THREATLOCKER_API_KEY"],
        default_org_id="default-org",
        base_url="https://api.example.test",
        timeout=5.0,
        log_level="WARNING",
        http_host="127.0.0.1",
        http_port=8765,
    )


# ---------------------------------------------------------------------------
# Basic request behaviour
# ---------------------------------------------------------------------------


async def test_get_sends_auth_and_default_org(httpx_mock, config):
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        json=[{"id": "abc"}],
        match_headers={
            "Authorization": "test-key",
            "ManagedOrganizationId": "default-org",
        },
    )
    async with ThreatLockerClient(config) as c:
        result = await c.get("/portalApi/Computer")
    assert result == [{"id": "abc"}]


async def test_org_override(httpx_mock, config):
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        json=[],
        match_headers={"ManagedOrganizationId": "child-org-1"},
    )
    async with ThreatLockerClient(config) as c:
        await c.get("/portalApi/Computer", organization_id="child-org-1")


async def test_empty_body_returns_sentinel(httpx_mock, config):
    """200 OK with no body should surface a clear marker, not silent None.

    Some ThreatLocker endpoints (action log / approval-request searches) reply with
    HTTP 200 + empty body when there are no rows. We want callers to see *something*
    instead of MCP's bare "no output" message.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        content=b"",
        status_code=200,
    )
    async with ThreatLockerClient(config) as c:
        result = await c.get("/portalApi/Computer")
    assert result == {"_empty_response": True, "_status_code": 200}


async def test_error_is_raised(httpx_mock, config):
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        status_code=403,
        json={"message": "forbidden"},
    )
    async with ThreatLockerClient(config) as c:
        with pytest.raises(ThreatLockerAPIError) as exc_info:
            await c.get("/portalApi/Computer")
    assert exc_info.value.status_code == 403
    assert "forbidden" in str(exc_info.value)


async def test_empty_body_204_returns_sentinel(httpx_mock, config):
    """204 No Content should also surface the sentinel so MCP doesn't drop it silently."""
    httpx_mock.add_response(
        method="POST",
        url="https://api.example.test/portalApi/Foo",
        status_code=204,
        content=b"",
    )
    async with ThreatLockerClient(config) as c:
        result = await c.post("/portalApi/Foo")
    assert result == {"_empty_response": True, "_status_code": 204}


async def test_json_null_body_returns_sentinel(httpx_mock, config):
    """200 OK with a JSON `null` body should also surface the sentinel.

    Some ThreatLocker endpoints (OnlineDevicesGetByParameters,
    ApprovalRequestGetByParameters) return the literal `null` instead of an empty body
    when there are no rows. Parsing that yields Python None, which MCP renders as
    "(completed with no output)" -- same UX problem as the empty-body case.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        content=b"null",
        status_code=200,
        headers={"content-type": "application/json"},
    )
    async with ThreatLockerClient(config) as c:
        result = await c.get("/portalApi/Computer")
    assert result == {"_empty_response": True, "_status_code": 200}


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


async def test_retries_on_503_then_succeeds(httpx_mock, config):
    """A 503 on the first attempt should be retried; success on second."""
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        status_code=503,
    )
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        json=[{"id": "ok"}],
    )
    async with ThreatLockerClient(config) as c:
        result = await c.get("/portalApi/Computer")
    assert result == [{"id": "ok"}]


async def test_raises_after_all_retries_exhausted(httpx_mock, config):
    """Three consecutive 503s should eventually raise ThreatLockerAPIError."""
    for _ in range(3):
        httpx_mock.add_response(
            method="GET",
            url="https://api.example.test/portalApi/Computer",
            status_code=503,
        )
    async with ThreatLockerClient(config) as c:
        with pytest.raises(ThreatLockerAPIError) as exc_info:
            await c.get("/portalApi/Computer")
    assert exc_info.value.status_code == 503


async def test_4xx_is_not_retried(httpx_mock, config):
    """A 404 should raise immediately without retrying."""
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        status_code=404,
        json={"message": "not found"},
    )
    async with ThreatLockerClient(config) as c:
        with pytest.raises(ThreatLockerAPIError) as exc_info:
            await c.get("/portalApi/Computer")
    assert exc_info.value.status_code == 404
    # Only one request should have been made
    assert len(httpx_mock.get_requests()) == 1


# ---------------------------------------------------------------------------
# Generated tool — camelCase serialisation
# ---------------------------------------------------------------------------


async def test_generated_tool_serializes_body_with_aliases(httpx_mock, monkeypatch, config):
    """End-to-end: a generated tool packs a Pydantic model into camelCase JSON."""
    from threatlocker_mcp import client as client_module
    from threatlocker_mcp import models

    # Inject our test client as the process-wide client
    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)

    httpx_mock.add_response(
        method="POST",
        url="https://api.example.test/portalapi/Computer/ComputerGetByAllParameters",
        json=[{"computerId": "abc"}],
    )

    from fastmcp import FastMCP

    from threatlocker_mcp.tools.computer import register

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("computer_get_by_all_parameters")
    await tool.run({"body": models.ComputerParameterDto(search_text="srv-01", page_size=50)})

    request = httpx_mock.get_request()
    import json as _json

    sent = _json.loads(request.content)
    # User-provided fields land with the right camelCase aliases and values.
    assert sent["searchText"] == "srv-01"
    assert sent["pageSize"] == 50
    # Non-nullable primitives (spec marks `nullable: false`) get their natural
    # zero/spec-default value rather than `null`, so they may also appear in
    # the body — that matches what the portal SPA sends and what the C# API
    # expects. The test no longer asserts a strict equality on the body.
    assert request.headers["Authorization"] == "test-key"
    assert request.headers["ManagedOrganizationId"] == "default-org"

    await test_client.close()


async def test_action_log_v2_defaults_usenewsearch_and_params_fields(
    httpx_mock, monkeypatch, config
):
    """action_log_get_by_parameters_v2 must default the `usenewsearch=true` header
    and ship `paramsFieldsDto: []` in the body.

    Both pieces are load-bearing: without `usenewsearch=true` the server silently
    returns an empty body even when data exists, and with `usenewsearch=true` but
    the field absent the server returns HTTP 500. Verified end-to-end against the
    live dev tenant on 2026-05-21 (see fix/action-log-empty-response).
    """
    from threatlocker_mcp import client as client_module
    from threatlocker_mcp import models

    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)

    httpx_mock.add_response(
        method="POST",
        url="https://api.example.test/portalapi/ActionLog/ActionLogGetByParametersV2",
        json=[],
    )

    from fastmcp import FastMCP

    from threatlocker_mcp.tools.action_log import register

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("action_log_get_by_parameters_v2")
    await tool.run(
        {
            "body": models.ActionLogParamsDto(
                source_table_id=1,
                start_date="2026-05-21T00:00:00Z",
                end_date="2026-05-22T00:00:00Z",
            )
        }
    )

    request = httpx_mock.get_request()
    import json as _json

    sent = _json.loads(request.content)
    # paramsFieldsDto must always appear, defaulted to [] — the server returns
    # HTTP 500 when it's missing under the new search path.
    assert "paramsFieldsDto" in sent, "paramsFieldsDto must be sent (default [])"
    assert sent["paramsFieldsDto"] == []
    # usenewsearch header must default to "true" so the call hits the path that
    # actually returns data.
    assert request.headers.get("usenewsearch") == "true"

    await test_client.close()


async def test_action_log_v2_back_compat_legacy_path(httpx_mock, monkeypatch, config):
    """Callers can opt out of the new-search path by passing usenewsearch=None
    explicitly. The MCP client suppresses the header when the value is None.
    """
    from threatlocker_mcp import client as client_module
    from threatlocker_mcp import models

    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)

    httpx_mock.add_response(
        method="POST",
        url="https://api.example.test/portalapi/ActionLog/ActionLogGetByParametersV2",
        json=[],
    )

    from fastmcp import FastMCP

    from threatlocker_mcp.tools.action_log import register

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("action_log_get_by_parameters_v2")
    await tool.run(
        {
            "body": models.ActionLogParamsDto(source_table_id=1),
            "usenewsearch": None,
        }
    )

    request = httpx_mock.get_request()
    assert "usenewsearch" not in {k.lower() for k in request.headers.keys()}

    await test_client.close()


async def test_approval_request_tool_camel_case(httpx_mock, monkeypatch, config):
    """approval_request_get_by_parameters serialises ApprovalRequestParametersDto correctly."""
    from threatlocker_mcp import client as client_module
    from threatlocker_mcp import models

    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)

    httpx_mock.add_response(
        method="POST",
        url="https://api.example.test/portalapi/ApprovalRequest/ApprovalRequestGetByParameters",
        json=[],
    )

    from fastmcp import FastMCP

    from threatlocker_mcp.tools.approval_request import register

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("approval_request_get_by_parameters")
    await tool.run(
        {
            "body": models.ApprovalRequestParametersDto(
                status_id=1, page_size=25, show_child_organizations=True
            )
        }
    )

    import json as _json

    sent = _json.loads(httpx_mock.get_request().content)
    assert sent["statusId"] == 1
    assert sent["pageSize"] == 25
    assert sent["showChildOrganizations"] is True

    await test_client.close()


# ---------------------------------------------------------------------------
# Retry-After header handling
# ---------------------------------------------------------------------------


def test_parse_retry_after_seconds():
    from threatlocker_mcp.client import _parse_retry_after

    assert _parse_retry_after("5") == 5.0
    assert _parse_retry_after("  2.5 ") == 2.5
    assert _parse_retry_after("0") == 0.0
    # Negative values are clamped to 0
    assert _parse_retry_after("-3") == 0.0


def test_parse_retry_after_invalid_returns_none():
    from threatlocker_mcp.client import _parse_retry_after

    assert _parse_retry_after(None) is None
    assert _parse_retry_after("") is None
    assert _parse_retry_after("not-a-date") is None


def test_parse_retry_after_http_date():
    """HTTP-date format should resolve to a non-negative delta from now."""
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime

    from threatlocker_mcp.client import _parse_retry_after

    future = datetime.now(timezone.utc) + timedelta(seconds=10)
    value = _parse_retry_after(format_datetime(future))
    assert value is not None
    # Should be close to 10s; allow generous slack for clock skew during test.
    assert 0 <= value <= 15


async def test_retries_honor_retry_after_seconds(httpx_mock, config, monkeypatch):
    """A 429 with Retry-After: 0 should retry quickly using the header value."""
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        status_code=429,
        headers={"Retry-After": "0"},
    )
    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalApi/Computer",
        json=[{"id": "ok"}],
    )

    sleeps: list[float] = []

    async def fake_sleep(d):
        sleeps.append(d)

    monkeypatch.setattr("threatlocker_mcp.client.asyncio.sleep", fake_sleep)

    async with ThreatLockerClient(config) as c:
        result = await c.get("/portalApi/Computer")
    assert result == [{"id": "ok"}]
    # Retry-After: 0 should produce a single sleep of 0 seconds (not the jitter).
    assert sleeps == [0.0]


# ---------------------------------------------------------------------------
# list_organizations tool
# ---------------------------------------------------------------------------


async def test_list_organizations_tool_registers_and_calls(httpx_mock, monkeypatch, config):
    """The Organization endpoint surfaces under the friendlier `list_organizations` name."""
    from threatlocker_mcp import client as client_module

    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)

    httpx_mock.add_response(
        method="GET",
        url="https://api.example.test/portalapi/Organization/OrganizationGetForMoveComputers?searchText=acme",
        json=[{"organizationId": "abc", "displayName": "Acme"}],
    )

    from fastmcp import FastMCP

    from threatlocker_mcp.tools.organization import register

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("list_organizations")
    assert tool is not None
    await tool.run({"search_text": "acme"})

    request = httpx_mock.get_request()
    assert "searchText=acme" in str(request.url)

    await test_client.close()


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_config_rejects_missing_api_key(monkeypatch):
    monkeypatch.delenv("THREATLOCKER_API_KEY", raising=False)
    monkeypatch.setenv("THREATLOCKER_API_KEY", "")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="THREATLOCKER_API_KEY"):
        Config.from_env()


def test_config_rejects_missing_org_id(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="THREATLOCKER_ORG_ID"):
        Config.from_env()


def test_config_rejects_invalid_base_url(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "some-org")
    monkeypatch.setenv("THREATLOCKER_BASE_URL", "ftp://bad.example.com")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="THREATLOCKER_BASE_URL"):
        Config.from_env()


def test_config_rejects_non_numeric_timeout(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "some-org")
    monkeypatch.setenv("THREATLOCKER_BASE_URL", "https://api.example.test")
    monkeypatch.setenv("THREATLOCKER_TIMEOUT", "not-a-number")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="THREATLOCKER_TIMEOUT"):
        Config.from_env()


def test_config_rejects_non_integer_port(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "some-org")
    monkeypatch.setenv("THREATLOCKER_BASE_URL", "https://api.example.test")
    monkeypatch.setenv("MCP_HTTP_PORT", "abc")
    from threatlocker_mcp.config import Config, ConfigError

    with pytest.raises(ConfigError, match="MCP_HTTP_PORT"):
        Config.from_env()


def test_config_strips_trailing_slash_from_base_url(monkeypatch):
    monkeypatch.setenv("THREATLOCKER_API_KEY", "some-key")
    monkeypatch.setenv("THREATLOCKER_ORG_ID", "some-org")
    monkeypatch.setenv("THREATLOCKER_BASE_URL", "https://api.example.test/")
    from threatlocker_mcp.config import Config

    config = Config.from_env()
    assert not config.base_url.endswith("/")
