"""Tests for the validated denied-activity search tool."""

from __future__ import annotations

import json

from fastmcp import FastMCP

from threatlocker_mcp import client as client_module
from threatlocker_mcp.client import ThreatLockerClient
from threatlocker_mcp.tools.denied_activity import _summarize
from threatlocker_mcp.tools.denied_activity import register


async def test_search_denied_activity_forces_deny_filters_and_paginates(
    httpx_mock, monkeypatch, config
):
    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)
    url = "https://api.example.test/portalapi/ActionLog/ActionLogGetByParametersV2"
    httpx_mock.add_response(
        method="POST",
        url=url,
        json=[
            {"action": "Deny", "hostname": "WS-01", "policyName": "Office"},
            {"action": "Permit", "hostname": "WS-02"},
        ],
    )
    httpx_mock.add_response(
        method="POST",
        url=url,
        json=[{"effectiveAction": "Blocked", "hostname": "WS-01", "totalCount": 9000000}],
    )

    mcp = FastMCP("test")
    register(mcp)
    tool = await mcp.get_tool("search_denied_activity")
    result = await tool.run(
        {
            "start_date": "2026-10-13T00:00:00Z",
            "end_date": "2026-10-14T00:00:00Z",
            "page_size": 2,
            "max_pages": 2,
            "organization_id": "target-org",
        }
    )

    requests = httpx_mock.get_requests()
    assert len(requests) == 2
    first_body = json.loads(requests[0].content)
    assert first_body["sourceTableId"] == 2
    assert first_body["onlyTrueDenies"] is True
    assert first_body["paramsFieldsDto"] == []
    assert first_body["pageNumber"] == 1
    assert first_body["pageSize"] == 2
    assert json.loads(requests[1].content)["pageNumber"] == 2
    assert requests[0].headers["usenewsearch"] == "true"
    assert requests[0].headers["ManagedOrganizationId"] == "target-org"
    assert result.structured_content["recordsReturned"] == 3
    assert result.structured_content["confirmedDenials"] == 2
    assert result.structured_content["recordsWithOtherExplicitActions"] == 1
    assert result.structured_content["hasMorePages"] is False
    assert result.structured_content["countMetadataWarning"] is not None
    assert result.structured_content["confirmedDenialsBy"]["hostname"][0] == {
        "value": "WS-01",
        "count": 2,
    }

    await test_client.close()


def test_summary_treats_missing_action_as_inconclusive():
    result = _summarize(
        [{"hostname": "WS-01", "action": None, "effectiveAction": None}],
        pages_fetched=1,
        page_size=50,
    )

    assert result["confirmedDenials"] == 0
    assert result["recordsWithUnclassifiedAction"] == 1
    assert "inconclusive" in result["interpretation"]
