"""Denial-focused action log search with response validation and summaries."""

from __future__ import annotations

from collections import Counter
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from ..client import get_client

_ENDPOINT = "/portalapi/ActionLog/ActionLogGetByParametersV2"
_DENY_VALUES = {"deny", "denied", "block", "blocked"}
_PERMIT_VALUES = {"permit", "permitted", "allow", "allowed"}


def _as_records(response: Any) -> list[dict[str, Any]]:
    if isinstance(response, list) and all(isinstance(row, dict) for row in response):
        return response
    if isinstance(response, dict):
        for key in ("items", "records", "results", "data"):
            value = response.get(key)
            if isinstance(value, list) and all(isinstance(row, dict) for row in value):
                return value
    raise ValueError("Unexpected action-log response shape; expected a list of records.")


def _action_values(record: dict[str, Any]) -> tuple[str, str]:
    action = str(record.get("action") or "").strip()
    effective_action = str(record.get("effectiveAction") or "").strip()
    return action, effective_action


def _classify_records(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    denied: list[dict[str, Any]] = []
    other_action: list[dict[str, Any]] = []
    unclassified: list[dict[str, Any]] = []
    for record in records:
        action, effective_action = _action_values(record)
        values = {action.lower(), effective_action.lower()} - {""}
        if values & _DENY_VALUES and not values & _PERMIT_VALUES:
            denied.append(record)
        elif values & (_DENY_VALUES | _PERMIT_VALUES):
            other_action.append(record)
        else:
            unclassified.append(record)
    return denied, other_action, unclassified


def _top_counts(records: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counts = Counter(str(record.get(field) or "Unknown") for record in records)
    return [{"value": value, "count": count} for value, count in counts.most_common(10)]


def _event_sample(record: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "eActionLogId",
        "dateTime",
        "hostname",
        "username",
        "action",
        "effectiveAction",
        "actionType",
        "policyName",
        "fullPath",
        "processPath",
        "createdByProcess",
        "hash",
        "sha256Hash",
    )
    return {field: record.get(field) for field in fields if record.get(field) is not None}


def _summarize(records: list[dict[str, Any]], pages_fetched: int, page_size: int) -> dict[str, Any]:
    denied, other_action, unclassified = _classify_records(records)
    action_counts = Counter(
        action or "(missing)"
        for record in records
        for action in _action_values(record)
    )
    total_count_values = sorted(
        {
            value
            for record in records
            if isinstance((value := record.get("totalCount")), int) and value >= 0
        }
    )
    result: dict[str, Any] = {
        "requestedSource": "deny action log",
        "recordsReturned": len(records),
        "pagesFetched": pages_fetched,
        "pageSize": page_size,
        "confirmedDenials": len(denied),
        "recordsWithOtherExplicitActions": len(other_action),
        "recordsWithUnclassifiedAction": len(unclassified),
        "actionFieldValues": dict(action_counts),
        "confirmedDenialsBy": {
            "hostname": _top_counts(denied, "hostname"),
            "policy": _top_counts(denied, "policyName"),
            "path": _top_counts(denied, "fullPath"),
        },
        "sampleConfirmedDenials": [_event_sample(row) for row in denied[:10]],
        "reportedTotalCountValues": total_count_values,
        "countMetadataWarning": (
            "The API-reported totalCount exceeds the number of rows fetched and was not "
            "used to infer results or control pagination."
            if any(value > len(records) for value in total_count_values)
            else None
        ),
        "hasMorePages": len(records) == pages_fetched * page_size,
    }
    if denied:
        result["interpretation"] = (
            "Only records with an explicit deny/block action and no conflicting permit "
            "action are counted as confirmed denials."
        )
    elif other_action:
        result["interpretation"] = (
            "The API returned explicit non-deny actions for this deny-log query; no "
            "confirmed denials were found in the fetched records."
        )
    else:
        result["interpretation"] = (
            "The API returned no explicit denial action values. Treat this response as "
            "inconclusive, not as evidence of zero denials."
        )
    if result["hasMorePages"]:
        result["paginationWarning"] = (
            "The page limit was reached or the final page was full. Increase max_pages "
            "or narrow the time range to continue searching."
        )
    return result


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="search_denied_activity",
        description=(
            "Search the ThreatLocker deny action log and return a compact, validated "
            "summary. Requires an ISO-8601 start/end time. Filters to sourceTableId=2 "
            "and onlyTrueDenies=true. Only explicit deny/block actions without a "
            "conflicting permit action count as confirmed denials. Pagination and "
            "page size are capped; narrow the time range or call again for more."
        ),
    )
    async def search_denied_activity(
        start_date: Annotated[str, Field(description="Inclusive ISO-8601 start date/time.")],
        end_date: Annotated[str, Field(description="Inclusive ISO-8601 end date/time.")],
        hostname: Annotated[str | None, Field(default=None)] = None,
        full_path: Annotated[str | None, Field(default=None)] = None,
        username: Annotated[str | None, Field(default=None)] = None,
        policy_id: Annotated[str | None, Field(default=None)] = None,
        page_size: Annotated[int, Field(ge=1, le=100, default=50)] = 50,
        max_pages: Annotated[int, Field(ge=1, le=10, default=3)] = 3,
        organization_id: Annotated[str | None, Field(default=None)] = None,
        override_organization_id: Annotated[str | None, Field(default=None)] = None,
    ) -> dict[str, Any]:
        """Search deny events, validate the returned action fields, and summarize."""
        client = await get_client()
        records: list[dict[str, Any]] = []
        pages_fetched = 0
        extra_headers = (
            {"OverrideManagedOrganizationId": override_organization_id}
            if override_organization_id is not None
            else None
        )

        for page_number in range(1, max_pages + 1):
            body: dict[str, Any] = {
                "sourceTableId": 2,
                "startDate": start_date,
                "endDate": end_date,
                "onlyTrueDenies": True,
                "paramsFieldsDto": [],
                "pageNumber": page_number,
                "pageSize": page_size,
                "sortBy": "dateTime",
                "sortDescending": True,
                "showTotalCount": True,
            }
            for key, value in (
                ("hostname", hostname),
                ("fullPath", full_path),
                ("username", username),
                ("policyId", policy_id),
            ):
                if value is not None:
                    body[key] = value

            response = await client.request(
                "POST",
                _ENDPOINT,
                organization_id=organization_id,
                json=body,
                extra_headers={
                    **(extra_headers or {}),
                    "usenewsearch": "true",
                },
            )
            page_records = _as_records(response)
            pages_fetched += 1
            records.extend(page_records)
            if len(page_records) < page_size:
                break

        return _summarize(records, pages_fetched, page_size)
