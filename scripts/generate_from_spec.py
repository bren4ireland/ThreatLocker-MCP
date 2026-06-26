"""Generate Pydantic models and FastMCP tool modules from the ThreatLocker OpenAPI spec.

Usage:
    python scripts/generate_from_spec.py spec.json

This is a one-shot codegen: it overwrites src/threatlocker_mcp/models.py and the
tool modules under src/threatlocker_mcp/tools/. Re-run whenever the spec changes.

Design choices:
- Only the curated CHOSEN_ENDPOINTS list below is wrapped as tools. To expand
  coverage, add more paths to that list.
- Schemas referenced (transitively) by any chosen endpoint are emitted as
  Pydantic models; unused schemas are skipped to keep the file readable.
- Query/path params become tool function arguments. JSON request bodies become
  a single typed `body` argument using the generated model.
"""

from __future__ import annotations

import json
import keyword
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Curated tool surface — (path, method) tuples we want exposed as MCP tools.
# Keep grouped by tag for readability.
# ---------------------------------------------------------------------------
# Per-endpoint description overrides. Appended to the swagger summary at codegen
# time. Use these to teach LLM callers about ThreatLocker API quirks that aren't
# visible in the spec — e.g. fields the schema marks optional but the server
# actually requires.
DESCRIPTION_OVERRIDES: dict[tuple[str, str], str] = {
    ("/portalapi/ActionLog/ActionLogGetByParametersV2", "post"): (
        " NOTE: this endpoint runs in two modes depending on the `usenewsearch`"
        " header. The MCP defaults to `usenewsearch=true` (the new search path the"
        " portal SPA uses), which is the only mode that returns data. Required:"
        " `sourceTableId` (1=ActionLog, 2=DenyActionLog, 3=BaselineActionLog,"
        " 4=EventLogActionLog), `startDate`, `endDate`, and `paramsFieldsDto`"
        " (the MCP defaults this to []; the server returns HTTP 500 when the field"
        " is absent under the new search path). Omitting `sourceTableId` returns"
        " HTTP 500; omitting both date forms returns 417 'Invalid Date Range'."
        " Pass `usenewsearch=null` to opt out into the legacy path -- but note"
        " the legacy path returns an empty body even when data exists, so this is"
        " only useful for back-compat probing."
    ),
    ("/portalapi/ApprovalRequest/ApprovalRequestGetByParameters", "post"): (
        " NOTE: `statusId` is required (e.g. 1 for Pending). Calls without it return"
        " HTTP 500. Each result's `requestorReason` is base64-encoded -- decode before"
        " display. For the decoded reason plus richer file/policy context, follow up"
        " with `approval_request_get_permit_application_by_id`."
    ),
    ("/portalapi/ApprovalRequest/ApprovalRequestGetById", "get"): (
        " NOTE: `requestorReason` is base64-encoded -- decode before display."
        " `approval_request_get_permit_application_by_id` returns the same request"
        " with the reason already decoded under `fileDetails.requestorReason`, plus"
        " file/policy/ringfencing context."
    ),
    ("/portalapi/ActionLog/ActionLogGetAllForFileHistoryV2", "get"): (
        " NOTE: spec marks every parameter optional, but the API returns 417 'Missing"
        " Parameters. Unable to load details.' unless `fullPath` plus one of"
        " (`hostname`, `computerId`) is supplied."
    ),
    ("/portalapi/ComputerGroup/ComputerGroupGetGroupAndComputer", "get"): (
        " NOTE: this endpoint can return very large payloads (>100KB for a single"
        " populated group) when called without scoping. Pass a specific"
        " `computerGroupId` and set only the `include_*` flags you actually need;"
        " unscoped calls may exceed downstream output limits."
    ),
    ("/portalapi/Computer/ComputerUpdateToFinishMaintenanceMode", "post"): (
        " Ends ACTIVE maintenance mode on a specific computer immediately."
        " Distinct from `maintenance_mode_end_by_id`, which ends a SCHEDULED"
        " maintenance window (in progress or not) identified by"
        " `maintenanceModeId`. Use this when you have a `computerId` and want"
        " enforcement re-enabled now. WARNING: may break in-progress installs."
    ),
    ("/portalapi/Organization/OrganizationGetForMoveComputers", "get"): (
        " Returns the organizations the current API key can target. Use this FIRST to"
        " discover org GUIDs to pass as `organization_id` to other tools. Despite the"
        " path name (the endpoint also feeds the portal's 'move computers' org"
        " picker), the result is the canonical list of accessible orgs for this key."
        " `searchText` filters by display name; pass an empty string for the full list."
    ),
    ("/portalapi/Application/ApplicationGetForApplicationOptions", "post"): (
        " List custom + built-in applications available to permit a file into."
        " Use this when the `permit_application` flow needs"
        " `useExistingApplication: true` -- i.e., adding the requested file to an"
        " app discovered through means other than `application_get_matching_list`."
        " Filter by `osType` (1=Windows, 2=MAC, 3=Linux, 5=Windows XP), optional"
        " `searchText` to narrow by name, and `includeBuiltIn` to include"
        " master-org BUILT-IN apps. (Renamed from the KB's"
        " `ApplicationGetListForAddToApplication`.)"
    ),
    ("/portalapi/Application/ApplicationGetForMaintenanceMode", "get"): (
        " List applications eligible for use with a Maintenance Mode when"
        " processing an approval request. Filter by `osType` (1=Windows, 2=MAC,"
        " 3=Linux, 5=Windows XP). Maintenance Modes (Installation/Learning/Monitor)"
        " are selected on the `permit_application` body via"
        " `policyConditions.ruleId` (1/2/3 respectively)."
    ),
    ("/portalapi/Application/ApplicationGetResearchDetailsById", "get"): (
        " Optional. Get ThreatLocker's research data (description, risks,"
        " mitigations) for an application before permitting it. Useful for"
        " decision support when the chosen `matchingApplication` or"
        " `existingApplication` is a sensitive built-in or unknown app."
    ),
    ("/portalapi/ApprovalRequest/ApprovalRequestPermitApplication", "post"): (
        " WORKFLOW: take_ownership -> get_permit_application_by_id ->"
        " application_get_matching_list -> permit_application. Start from the"
        " DTO returned by get_permit_application_by_id and modify the choices"
        " below."
        " REQUIRED FIELDS (KB-documented, all must be present):"
        " `approvalRequest.approvalRequestId`;"
        " `approvalRequest.json` -- copy verbatim from"
        " get_permit_application_by_id (server uses it to reconstruct"
        " file/action context, omitting it causes silent failures);"
        " `userinstance` -- the portal shard ('h', 'g', etc.), parsed from the"
        " request's `portalApiUrl` subdomain;"
        " `isFromApproval: true`; `hasOriginApprovalCenter: true`;"
        " `actionType` (copy from request: 'elevate'/'execute'/'install');"
        " `osType` (1=Windows, 2=Mac, 3=Linux, 5=WinXP);"
        " `organizationId`, `computerId` (copy from request);"
        " `organizationIds` -- list of parent org IDs above the request's org"
        " (`[]` for top-level); `fileDetails.fullPath`."
        " APP SELECTION (set exactly ONE mode on `matchingApplications`):"
        " (a) PREFERRED -- use `application_get_matching_list` result. Prefer"
        " tenant-owned match (its `organizationId` equals the call's"
        " `organizationId`) over master-org/BUILT-IN (`organizationName:"
        ' "master"`). Set `useMatchingApplication: true`, populate'
        " `matchingApplication` with the chosen result; set others false and"
        " their objects to `null`. The DTO's `hasMatchingApplication` flag is"
        " UNRELIABLE -- trust `application_get_matching_list.hasMatching`"
        " instead."
        " *** CRITICAL -- BUILT-IN match REQUIRES entire-org scope. When the"
        ' chosen match has `organizationName: "master"`, you MUST set'
        " `policyLevel.toEntireOrganization: true`. Pairing a BUILT-IN with"
        " computer-scope returns HTTP 401 \"Missing the '' permission\""
        " (misleading -- it's actually a body-shape error). Verified"
        " 2026-05-21. Tenant-owned matches and new apps use the default"
        " all-flags-false scope."
        " (b) FALLBACK -- add to existing custom app (discover via"
        " `application_get_for_application_options`). Set"
        " `useExistingApplication: true`, populate `existingApplication`;"
        " others null."
        " (c) LAST RESORT -- create new app. Set `useNewApplication: true` and"
        " `newApplicationName` to a non-null derived name (e.g. file stem"
        ' title-cased: `vlc.exe` -> "VLC"). Null returns HTTP 417'
        " 'Must enter a name for a new application'."
        " POLICY (`policyConditions.ruleId`): 0=manual rules, 1=Install Mode"
        " 1hr, 2=Learning Mode 1hr, 3=Monitor Mode 1hr. Set"
        " `useExistingPolicy: true` to reuse an existing policy"
        " (`manualOptions` then carries the rule criteria)."
        " SCOPE (`policyLevel`): default 'this computer' = ALL THREE flags"
        " false (`toEntireOrganization`/`toComputerGroup`/`toComputer`);"
        " scope is inferred from top-level `computerId`. Setting"
        " `toComputer: true` returns HTTP 417 'Provided applies to ID does"
        " not associate with a known OS type'. For computer group, set"
        " `toComputerGroup: true` and populate `selectedComputerGroup`"
        " (discover via `computer_group_get_dropdown_by_organization_id`)."
        " For entire-org, set `toEntireOrganization: true`."
        " ACTION TYPE: for elevate set `isElevationRequest: true` and"
        " `isExecutionRequest: false`; for execute reverse. Both are"
        " spec-readOnly but MUST be sent matching the action."
        " SHAPE: send `null` (not omit) for unused sub-objects --"
        " `matchingApplication`, `existingApplication`, `selectedComputerGroup`,"
        " `policyExpirationDate`, `elevationExpirationDate`. Wrong shape ="
        " opaque HTTP 500."
        " PERMISSIONS: API key user needs one of 'Approve for Entire"
        " Organization', 'Approve for Group', 'Approve for Single Computer',"
        " or 'Approve for Single Computer Application Only' in Administrators."
    ),
    ("/portalapi/MaintenanceMode/MaintenanceModeUpdateEndDateTimeForSpecificDate", "post"): (
        " Reschedules the end time of an existing maintenance window for a"
        " specific computer without terminating it. Pass the new"
        " `maintenanceEndDate` (ISO 8601 UTC). To END maintenance immediately"
        " use `computer_update_to_finish_maintenance_mode` (by computer) or"
        " `maintenance_mode_end_by_id` (by maintenance schedule)."
    ),
    ("/portalapi/ApprovalRequest/ApprovalRequestPermitStorageApproval", "post"): (
        " NOT YET LIVE-TESTED -- expect shape sensitivity similar to"
        " `approval_request_permit_application`. WORKFLOW: take_ownership ->"
        " get_storage_approval_by_id -> permit_storage_approval. Start from"
        " the DTO returned by `approval_request_get_storage_approval_by_id`"
        " and modify the choices below."
        " LIKELY REQUIRED (by analogy with the application-permit flow):"
        " `approvalRequest` -- copy verbatim from get_storage_approval_by_id;"
        " `json` -- verbatim copy from the same response, used by the server"
        " to reconstruct the storage-request context."
        " DEVICE / SCOPE FLAGS (set exactly one mode):"
        " `addDeviceToExisting` -- add the storage device to an existing"
        " storage policy (populate `existingStoragePolicy`);"
        " `deviceExists` -- the device is already known to ThreatLocker;"
        " `allStorageDevices` -- apply to all storage devices in scope;"
        " `allFilePaths` -- apply to all paths rather than just"
        " `selectedPath`;"
        " `allUserGroups` -- apply to all users/groups rather than the"
        " populated `usersList`/`userGroups`."
        " Set unused companion objects (`existingStoragePolicy`,"
        " `newStorageDevice`) to `null`, not omitted."
        " EXPIRATION: `expirationDate` is ISO 8601 UTC; null = permanent."
        " RESPONSE: `responseSubject` and `responseReason` are shown to the"
        " requester; `notifyOnResponse` controls whether they're emailed."
        " If the server returns HTTP 401 \"Missing the '' permission\""
        " (empty interpolation), suspect body-shape rather than permissions"
        " -- same root cause as the application-permit flow."
    ),
    ("/portalapi/Tag/TagUpdate", "post"): (
        " Updates an existing tag. `tagId` (spec-nullable) must be a valid"
        " existing tag GUID; passing an empty or omitted `tagId` may cause"
        " the server to interpret the request as a new-tag creation. Use"
        " `tag_get_dropdown_options_by_organization_id` to discover existing"
        " tag GUIDs first. `tagType` enum (verify against tenant): 1=Computer"
        " tag, 2=Application tag, 3=Network tag. Sending one of"
        " `tagItemsText` / `tagItemsIPv4` / `tagItemsIPv6` replaces (not"
        " merges) that list for the tag. NOT YET LIVE-TESTED -- verify"
        " behaviour against the dev tenant before relying on it."
    ),
}

# Query/header params the API actually requires but that the spec marks optional.
# Keys are (path, method); values are sets of swagger parameter names. Listed names
# get promoted to required in the generated tool signature so callers fail loudly
# instead of getting an opaque 417 from the server. Only use this when the swagger
# unambiguously needs one specific field -- if the API accepts either of two
# alternatives (e.g. hostname OR computerId), document it in DESCRIPTION_OVERRIDES
# instead, since a single-param promotion can't express one-of semantics.
REQUIRED_PARAM_OVERRIDES: dict[tuple[str, str], set[str]] = {
    # The spec marks all three query params optional, but the tag-dropdown
    # endpoint follows the standard portal-API pattern (e.g. statusId on
    # ApprovalRequestGetByParameters) where a missing required field returns
    # HTTP 500. Promote them to required so callers fail loudly. If live-test
    # reveals one is actually tolerated, demote it.
    ("/portalapi/Tag/TagGetDowndownOptionsByOrganizationId", "get"): {
        "includeBuiltIns",
        "tagType",
        "includeNetworkTagInMaster",
    },
}


# Default values to inject for header parameters when the caller doesn't pass one.
# Keys are (path, method); values map swagger header-parameter name to the literal
# string default. Use this when the portal SPA always sends a particular header
# value at runtime that's required for the endpoint to behave correctly, but the
# spec doesn't mark it required and doesn't surface the value. Callers can still
# override by passing the parameter explicitly (including `None` to opt out).
HEADER_PARAM_DEFAULTS: dict[tuple[str, str], dict[str, str]] = {
    # The new-search path is the only mode that returns data; the legacy path
    # silently returns an empty body. Verified 2026-05-21 against the portal
    # capture for the dev tenant's Unified Audit page.
    ("/portalapi/ActionLog/ActionLogGetByParametersV2", "post"): {
        "usenewsearch": "true",
    },
}


# Per-property field overrides for generated Pydantic models. Use when the spec
# default doesn't match what the server actually requires -- for example, when a
# field that's marked nullable in the spec is in practice required by the server
# under some request modes. The override replaces the Field(default=..., ...) line
# emitted by the default codegen, so include both `type` and `default` together.
# `type` is the bare Python type (no `| None` — the override implies non-nullable).
# `default` is the full Field-argument string (e.g. "default_factory=list").
PROPERTY_FIELD_OVERRIDES: dict[str, dict[str, dict[str, str]]] = {
    "ActionLogParamsDto": {
        # The new-search code path (usenewsearch=true) returns HTTP 500 when this
        # field is absent — even though the spec marks it nullable. Default to []
        # so the wire body always carries the field. Verified 2026-05-21 by
        # bisecting against the portal-captured working body.
        "paramsFieldsDto": {
            "type": "list[ParamsFieldsDto]",
            "default": "default_factory=list",
        },
    },
}

# Per-schema property name overrides. Some spec property names are mis-cased relative
# to what the live API actually returns and accepts -- e.g. ThreatLockerActionDto
# declares `fullpath`/`policyid`/`actionid` all-lowercase and `SerialNumber`/`DomainName`
# PascalCase, but the API consistently uses `fullPath`/`policyId`/`actionId`/
# `serialNumber`/`domainName`. Mapping each spec name to a canonical name here makes
# the generated model use the canonical name as the Pydantic alias, so on-the-wire
# JSON matches the live API and `extra="allow"` doesn't end up emitting duplicate
# casings on round-trip (verified 2026-05-21 against a captured permit body).
PROPERTY_NAME_OVERRIDES: dict[str, dict[str, str]] = {
    "ThreatLockerActionDto": {
        "fullpath": "fullPath",
        "policyid": "policyId",
        "actionid": "actionId",
        "SerialNumber": "serialNumber",
        "DomainName": "domainName",
    },
}

# Override the auto-derived tool name for specific endpoints. Use this when the
# endpoint's path-derived name is awkward for LLM callers (e.g. an org-listing
# endpoint nominally scoped to a "move computers" UI is better surfaced as the
# generic `list_organizations`). The override only affects the MCP tool name and
# the Python function name; the underlying path/method is unchanged.
TOOL_NAME_OVERRIDES: dict[tuple[str, str], str] = {
    ("/portalapi/Organization/OrganizationGetForMoveComputers", "get"): "list_organizations",
    # The spec path has a typo ("Downdown" instead of "Dropdown"). Mask it from
    # the LLM-facing tool name; the underlying path is unchanged.
    (
        "/portalapi/Tag/TagGetDowndownOptionsByOrganizationId",
        "get",
    ): "tag_get_dropdown_options_by_organization_id",
}


# Endpoints that need the full DTO serialized -- including explicit `null` fields --
# rather than the default `exclude_none=True` behavior. Most ThreatLocker endpoints
# tolerate stripped nulls (they're queries/filters), but a few permit-style endpoints
# treat absent fields differently from `null` and reject the request with HTTP 500
# when nulls are dropped. Add (path, method) tuples here when you confirm an endpoint
# needs the full shape.
SEND_FULL_BODY_OVERRIDES: set[tuple[str, str]] = {
    # Permit requires explicit `null` values on policyExpirationDate,
    # elevationExpirationDate, isExecutionRequest, isRingfenced, and the null-filled
    # sub-objects under matchingApplications / policyLevel. Stripping them returns
    # an opaque HTTP 500. Verified by diffing our failing body against the captured
    # working portal traffic on 2026-05-21.
    ("/portalapi/ApprovalRequest/ApprovalRequestPermitApplication", "post"),
}


CHOSEN_ENDPOINTS: list[tuple[str, str]] = [
    # Computer (9)
    ("/portalapi/Computer/ComputerGetByAllParameters", "post"),
    ("/portalapi/Computer/ComputerGetForEditById", "get"),
    ("/portalapi/Computer/ComputerUpdateForEdit", "patch"),
    ("/portalapi/Computer/ComputerEnableProtection", "post"),
    ("/portalapi/Computer/ComputerDisableProtection", "post"),
    ("/portalapi/Computer/ComputerUpdateMaintenanceMode", "post"),
    ("/portalapi/Computer/ComputerMoveToOtherOrganization", "post"),
    ("/portalapi/Computer/ComputerUpdateBaselineRescan", "post"),
    ("/portalapi/Computer/ComputerUpdateToFinishMaintenanceMode", "post"),
    # ApprovalRequest (11)
    # Note: AuthorizeForPermitById is intentionally NOT exposed -- 2026-05 probe
    # against a pending elevate request showed it 400s with "Approval Request
    # already actioned by " (empty actor interpolation), even after
    # UpdateForTakeOwnership. The official KB
    # (threatlocker.kb.help/processing-application-control-approval-requests-through-api)
    # does not document it as an approve path; it appears to be a multi-tier
    # MSP-only "pre-authorize for downstream permit" workflow. The canonical
    # approve path is ApprovalRequestPermitApplication.
    ("/portalapi/ApprovalRequest/ApprovalRequestGetByParameters", "post"),
    ("/portalapi/ApprovalRequest/ApprovalRequestGetById", "get"),
    ("/portalapi/ApprovalRequest/ApprovalRequestGetCount", "get"),
    ("/portalapi/ApprovalRequest/ApprovalRequestGetPermitApplicationById", "get"),
    ("/portalapi/ApprovalRequest/ApprovalRequestPermitApplication", "post"),
    ("/portalapi/ApprovalRequest/ApprovalRequestUpdateForReject", "post"),
    ("/portalapi/ApprovalRequest/ApprovalRequestUpdateForIgnore", "post"),
    ("/portalapi/ApprovalRequest/ApprovalRequestUpdateForTakeOwnership", "post"),
    ("/portalapi/ApprovalRequest/ApprovalRequestGetStorageApprovalById", "get"),
    ("/portalapi/ApprovalRequest/ApprovalRequestPermitStorageApproval", "post"),
    ("/portalapi/ApprovalRequest/ApprovalRequestGetFileDownloadDetailsById", "get"),
    # ActionLog (4)
    ("/portalapi/ActionLog/ActionLogGetByParametersV2", "post"),
    ("/portalapi/ActionLog/ActionLogGetByIdV2", "get"),
    ("/portalapi/ActionLog/ActionLogGetAllForFileHistoryV2", "get"),
    ("/portalapi/ActionLog/ActionLogGetFileDownloadDetailsById", "get"),
    # SystemAudit (2)
    ("/portalapi/SystemAudit/SystemAuditGetByParameters", "post"),
    ("/portalapi/SystemAudit/SystemAuditGetForHealthCenter", "post"),
    # ComputerGroup (2)
    ("/portalapi/ComputerGroup/ComputerGroupGetGroupAndComputer", "get"),
    ("/portalapi/ComputerGroup/ComputerGroupGetDropdownByOrganizationId", "get"),
    # MaintenanceMode (4)
    ("/portalapi/MaintenanceMode/MaintenanceModeGetByComputerId", "get"),
    ("/portalapi/MaintenanceMode/MaintenanceModeInsert", "post"),
    ("/portalapi/MaintenanceMode/MaintenanceModeEndById", "patch"),
    ("/portalapi/MaintenanceMode/MaintenanceModeUpdateEndDateTimeForSpecificDate", "post"),
    # Application (5)
    ("/portalapi/Application/ApplicationGetById", "get"),
    ("/portalapi/Application/ApplicationGetMatchingList", "post"),
    # Helpers documented in the ThreatLocker KB approval-flow article. The KB
    # called the first one `ApplicationGetListForAddToApplication` but the
    # current spec ships it as `ApplicationGetForApplicationOptions`.
    ("/portalapi/Application/ApplicationGetForApplicationOptions", "post"),
    ("/portalapi/Application/ApplicationGetForMaintenanceMode", "get"),
    ("/portalapi/Application/ApplicationGetResearchDetailsById", "get"),
    # Policy (1)
    ("/portalapi/Policy/PolicyGetById", "get"),
    # OnlineDevices (1)
    ("/portalapi/OnlineDevices/OnlineDevicesGetByParameters", "get"),
    # Report (1)
    ("/portalapi/Report/ReportGetByOrganizationId", "get"),
    # Organization (1) — list-orgs surfaced as `list_organizations` via TOOL_NAME_OVERRIDES
    ("/portalapi/Organization/OrganizationGetForMoveComputers", "get"),
    # Tag (3)
    ("/portalapi/Tag/TagGetById", "get"),
    ("/portalapi/Tag/TagGetDowndownOptionsByOrganizationId", "get"),
    ("/portalapi/Tag/TagUpdate", "post"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def snake(name: str) -> str:
    """CamelCase -> snake_case, avoiding Python keywords and Pydantic BaseModel attrs."""
    s = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    s = re.sub(r"[^a-z0-9_]+", "_", s).strip("_")
    # Avoid Python keywords and names that shadow BaseModel methods/attrs.
    shadowed = {
        "id",
        "type",
        "json",
        "schema",
        "fields",
        "dict",
        "copy",
        "construct",
        "parse_obj",
        "parse_raw",
        "validate",
        "model_dump",
        "model_config",
        "model_fields",
    }
    if keyword.iskeyword(s) or s in shadowed:
        s = s + "_"
    return s


def safe_name(name: str) -> str:
    """Make a string a valid Python identifier."""
    s = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if s and s[0].isdigit():
        s = "_" + s
    return s


def operation_id_to_func(path: str, method: str) -> str:
    """Turn '/portalapi/Computer/ComputerGetByAllParameters' POST into
    'computer_get_by_all_parameters'. Honors TOOL_NAME_OVERRIDES for endpoints
    that should be surfaced under a different LLM-facing name."""
    override = TOOL_NAME_OVERRIDES.get((path, method))
    if override:
        return override
    tail = path.rsplit("/", 1)[-1]
    return snake(tail)


def path_to_description(path: str, method: str) -> str:
    """Derive a readable description from a path when the spec has no summary.

    '/portalapi/ActionLog/ActionLogGetByIdV2', 'get'
    → 'Action Log: Get By Id V2'
    """
    tail = path.rsplit("/", 1)[-1]
    # Strip a common prefix that repeats the tag (e.g. "ActionLog" in "ActionLogGetByIdV2")
    parts = path.strip("/").split("/")
    tag_segment = parts[-2] if len(parts) >= 2 else ""
    if tag_segment and tail.startswith(tag_segment):
        tail = tail[len(tag_segment) :]
    # CamelCase → words
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", tail).strip()
    tag_words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", tag_segment).strip()
    return f"{tag_words}: {words}" if tag_words and words else (words or f"{method.upper()} {path}")


def _iter_refs(node: Any):
    """Yield every $ref string found anywhere in a JSON-schema fragment."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str):
                yield v
            else:
                yield from _iter_refs(v)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_refs(item)


def collect_referenced_schemas(spec: dict, start_refs: list[str]) -> set[str]:
    """BFS the $ref graph starting from a list of schema names."""
    schemas = spec["components"]["schemas"]
    seen: set[str] = set()
    queue = list(start_refs)
    while queue:
        name = queue.pop()
        if name in seen or name not in schemas:
            continue
        seen.add(name)
        for ref in _iter_refs(schemas[name]):
            ref_name = ref.rsplit("/", 1)[-1]
            if ref_name not in seen:
                queue.append(ref_name)
    return seen


# ---------------------------------------------------------------------------
# Schema -> Python type
# ---------------------------------------------------------------------------
PRIMITIVE_TYPES = {
    "string": "str",
    "integer": "int",
    "number": "float",
    "boolean": "bool",
}


def py_type_for_schema(schema: dict, models_in_scope: set[str]) -> str:
    """Translate a JSON-schema fragment into a Python type expression.

    Conservative: anything we don't recognize falls back to Any.
    """
    if not isinstance(schema, dict):
        return "Any"

    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        return name if name in models_in_scope else "Any"

    if "allOf" in schema and len(schema["allOf"]) == 1:
        return py_type_for_schema(schema["allOf"][0], models_in_scope)

    if "oneOf" in schema or "anyOf" in schema:
        # Take the first option; this API doesn't really use unions meaningfully.
        # Emit a stderr warning so future spec changes that add real unions don't
        # silently lose type info.
        opts = schema.get("oneOf") or schema.get("anyOf")
        if opts and len(opts) > 1:
            print(
                f"WARNING: collapsing oneOf/anyOf with {len(opts)} options to first option",
                file=sys.stderr,
            )
        if opts:
            return py_type_for_schema(opts[0], models_in_scope)
        return "Any"

    t = schema.get("type")
    if t == "array":
        inner = py_type_for_schema(schema.get("items", {}), models_in_scope)
        return f"list[{inner}]"

    if t == "object":
        # additionalProperties dict
        ap = schema.get("additionalProperties")
        if isinstance(ap, dict):
            inner = py_type_for_schema(ap, models_in_scope)
            return f"dict[str, {inner}]"
        return "dict[str, Any]"

    if t in PRIMITIVE_TYPES:
        base = PRIMITIVE_TYPES[t]
        fmt = schema.get("format")
        if t == "string" and fmt == "uuid":
            return "str"  # keep as str; the API accepts string UUIDs
        if t == "string" and fmt in ("date-time", "date"):
            return "str"
        return base

    return "Any"


def emit_model(name: str, schema: dict, models_in_scope: set[str]) -> str:
    """Emit a Pydantic model class for one schema."""
    if schema.get("type") != "object" and "properties" not in schema:
        # Type alias for non-object schemas (rare in this API)
        py = py_type_for_schema(schema, models_in_scope)
        return f"{name} = {py}\n\n"

    props = schema.get("properties", {})
    required = set(schema.get("required", []))

    lines = [f"class {name}(BaseModel):"]
    if not props:
        lines.append("    model_config = ConfigDict(extra='allow')")
        lines.append("    pass")
        lines.append("")
        return "\n".join(lines) + "\n"

    lines.append("    model_config = ConfigDict(populate_by_name=True, extra='allow')")

    overrides = PROPERTY_NAME_OVERRIDES.get(name, {})
    field_overrides = PROPERTY_FIELD_OVERRIDES.get(name, {})
    for prop_name, prop_schema in props.items():
        # If the spec name is mis-cased relative to the live API, use the canonical
        # name for both the Pydantic alias and the snake_case derivation. The original
        # `prop_name` is still what appears in the spec's `required` array.
        canonical = overrides.get(prop_name, prop_name)

        # Per-property field override — when set, we emit a tailored field line
        # that bypasses the spec-derived type/default logic. Used for fields where
        # the spec default doesn't match what the server actually requires.
        field_override = field_overrides.get(prop_name)
        if field_override:
            py_field = snake(canonical)
            override_type = field_override["type"]
            override_default = field_override["default"]
            alias_arg = f'alias="{canonical}"' if py_field != canonical else ""
            field_args = ", ".join(a for a in [override_default, alias_arg] if a)
            lines.append(f"    {py_field}: {override_type} = Field({field_args})")
            continue

        py_type = py_type_for_schema(prop_schema, models_in_scope)
        py_field = snake(canonical)
        is_required = prop_name in required
        nullable = prop_schema.get("nullable", False)
        spec_type = prop_schema.get("type")

        # Non-nullable primitives (integer / number / boolean) get their type's
        # natural zero default rather than `T | None = None`. The ThreatLocker
        # API rejects `null` for these fields with HTTP 400 even though the
        # spec doesn't list them in `required` — C# value-type semantics, where
        # absent ~= zero but null is invalid. Verified end-to-end against the
        # permit_application endpoint after exclude_none=False was enabled.
        is_non_nullable_primitive = spec_type in {"integer", "number", "boolean"} and not nullable

        if is_non_nullable_primitive:
            # Honor an explicit spec `default` if present, else use the type's zero.
            spec_default = prop_schema.get("default")
            if spec_type == "boolean":
                default_expr = "True" if spec_default is True else "False"
            elif spec_type == "integer":
                default_expr = str(spec_default) if isinstance(spec_default, int) else "0"
            else:  # number
                default_expr = (
                    str(spec_default) if isinstance(spec_default, (int, float)) else "0.0"
                )
        elif not is_required or nullable:
            py_type = f"{py_type} | None"
            default_expr = "None"
        else:
            default_expr = None  # required + non-primitive: no default emitted

        desc = prop_schema.get("description") or prop_schema.get("title")
        alias_arg = f'alias="{canonical}"' if py_field != canonical else ""
        desc_arg = f"description={desc!r}" if desc else ""
        default_arg = f"default={default_expr}" if default_expr is not None else ""
        field_args = ", ".join(a for a in [default_arg, alias_arg, desc_arg] if a)

        if field_args:
            lines.append(f"    {py_field}: {py_type} = Field({field_args})")
        elif default_expr is not None:
            lines.append(f"    {py_field}: {py_type} = {default_expr}")
        else:
            lines.append(f"    {py_field}: {py_type}")

    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------
def generate_models(spec: dict, needed_schemas: set[str]) -> str:
    schemas = spec["components"]["schemas"]

    # Topologically sort by reference depth so simple types come before composite ones.
    # Pydantic v2 handles forward refs fine, but ordering keeps the file readable.
    order: list[str] = []
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited or name not in needed_schemas:
            return
        visited.add(name)
        for ref in _iter_refs(schemas.get(name, {})):
            visit(ref.rsplit("/", 1)[-1])
        order.append(name)

    for n in sorted(needed_schemas):
        visit(n)

    parts = [
        '"""Pydantic models generated from the ThreatLocker OpenAPI spec.',
        "",
        "Do not edit by hand. Regenerate via `python scripts/generate_from_spec.py spec.json`.",
        '"""',
        "from __future__ import annotations",
        "",
        "from typing import Any",
        "",
        "from pydantic import BaseModel, ConfigDict, Field",
        "",
        "",
    ]

    for name in order:
        parts.append(emit_model(name, schemas[name], needed_schemas))

    # Resolve forward refs (only for actual model classes, not type aliases)
    parts.append("# Resolve any forward references")
    for name in order:
        sch = schemas[name]
        is_class = sch.get("type") == "object" or "properties" in sch
        if is_class:
            parts.append(f"{name}.model_rebuild()")
    parts.append("")

    return "\n".join(parts)


def generate_tools_module(
    tag: str,
    ops: list[tuple[str, str, dict]],
    models_in_scope: set[str],
) -> str:
    """Generate a per-tag tool module."""
    lines = [
        f'"""ThreatLocker MCP tools for tag: {tag}.',
        "",
        "Generated by scripts/generate_from_spec.py. Do not edit by hand.",
        '"""',
        "from __future__ import annotations",
        "",
        "from typing import Annotated, Any",
        "",
        "from fastmcp import FastMCP",
        "from pydantic import Field",
        "",
    ]

    # Only import models when this tag has at least one body parameter.
    needs_models = any(
        (op.get("requestBody") or {}).get("content", {}).get("application/json") for _, _, op in ops
    )
    if needs_models:
        lines.append("from .. import models")
    lines += [
        "from ..client import get_client",
        "",
        "",
        "def register(mcp: FastMCP) -> None:",
    ]

    for path, method, op in ops:
        func_name = operation_id_to_func(path, method)
        summary = (op.get("summary") or op.get("description") or "").strip()
        # First line only, escaped
        first_line = (
            summary.split("\n")[0].strip() if summary else path_to_description(path, method)
        )
        # Full description (cleaned up for the docstring)
        full_desc = summary.replace("\r\n", "\n").strip() or first_line
        override = DESCRIPTION_OVERRIDES.get((path, method))
        if override:
            first_line = (first_line + override).strip()
            full_desc = (full_desc + override).strip()

        # Build argument list as (text, has_default) so we can sort.
        required_args: list[str] = []
        optional_args: list[str] = []
        params_dict_items: list[tuple[str, str]] = []  # (py_name, source_name)
        body_arg: str | None = None

        parameters = op.get("parameters", [])
        query_params = [p for p in parameters if p.get("in") == "query"]
        header_params = [
            p
            for p in parameters
            if p.get("in") == "header"
            and p.get("name")
            not in ("Authorization", "ManagedOrganizationId", "OverrideManagedOrganizationId")
        ]

        forced_required = REQUIRED_PARAM_OVERRIDES.get((path, method), set())
        for p in query_params:
            name = p["name"]
            py_name = snake(name)
            sch = p.get("schema", {})
            py_type = py_type_for_schema(sch, models_in_scope)
            required = p.get("required", False) or name in forced_required
            desc = (p.get("description") or "").replace("\n", " ").strip()
            desc_kw = f"description={desc!r}, " if desc else ""
            if required:
                if desc:
                    required_args.append(
                        f"        {py_name}: Annotated[{py_type}, Field(description={desc!r})]"
                    )
                else:
                    required_args.append(f"        {py_name}: {py_type}")
            else:
                opt_type = f"{py_type} | None"
                optional_args.append(
                    f"        {py_name}: Annotated[{opt_type}, Field({desc_kw}default=None)] = None"
                )
            params_dict_items.append((py_name, name))

        # Custom (non-auth) header params, if any. Per-endpoint defaults from
        # HEADER_PARAM_DEFAULTS get applied so the caller doesn't have to know
        # about portal-SPA-only headers.
        endpoint_header_defaults = HEADER_PARAM_DEFAULTS.get((path, method), {})
        for p in header_params:
            name = p["name"]
            py_name = snake(name)
            header_default = endpoint_header_defaults.get(name)
            if header_default is not None:
                optional_args.append(
                    f'        {py_name}: Annotated[str | None, Field(description="Header: {name}", default={header_default!r})] = {header_default!r}'
                )
            else:
                optional_args.append(
                    f'        {py_name}: Annotated[str | None, Field(description="Header: {name}", default=None)] = None'
                )

        # Request body
        body_schema_ref = None
        req_body = op.get("requestBody") or {}
        content = req_body.get("content", {}).get("application/json", {})
        if content:
            sch = content.get("schema", {})
            if "$ref" in sch:
                body_schema_ref = sch["$ref"].rsplit("/", 1)[-1]
            elif sch.get("type") == "array" and "$ref" in sch.get("items", {}):
                inner = sch["items"]["$ref"].rsplit("/", 1)[-1]
                body_schema_ref = f"list[models.{inner}]"

        if body_schema_ref:
            if body_schema_ref.startswith("list["):
                # required — no default
                required_args.append(
                    f'        body: Annotated[{body_schema_ref}, Field(description="Request body (array).")]'
                )
            else:
                required_args.append(
                    f'        body: Annotated[models.{body_schema_ref}, Field(description="Request body.")]'
                )
            body_arg = body_schema_ref

        # Org override is always optional
        optional_args.append(
            '        organization_id: Annotated[str | None, Field(description="Override the default organization (ManagedOrganizationId header).", default=None)] = None'
        )
        optional_args.append(
            '        override_organization_id: Annotated[str | None, Field(description="Optional OverrideManagedOrganizationId header.", default=None)] = None'
        )

        # Required args first, optional args (with defaults) after. Python syntax requires this.
        args = required_args + optional_args
        sig = ",\n".join(args)
        docstring_desc = full_desc.replace('"""', "'''")[:4000]

        # Body of function
        params_build = ""
        if params_dict_items:
            items_code = ", ".join(f'"{src}": {var}' for var, src in params_dict_items)
            params_build = (
                f"        params = {{{items_code}}}\n"
                f"        params = {{k: v for k, v in params.items() if v is not None}}\n"
            )

        if body_arg:
            exclude_none = (path, method) not in SEND_FULL_BODY_OVERRIDES
            if body_arg.startswith("list["):
                body_line = f"        body_json = [b.model_dump(by_alias=True, exclude_none={exclude_none}) for b in body]\n"
            else:
                body_line = f"        body_json = body.model_dump(by_alias=True, exclude_none={exclude_none})\n"
        else:
            body_line = ""

        # extra_headers for OverrideManagedOrganizationId etc.
        header_block = (
            "        extra_headers = {}\n"
            "        if override_organization_id is not None:\n"
            "            extra_headers['OverrideManagedOrganizationId'] = override_organization_id\n"
        )
        # custom header params (rare)
        for p in header_params:
            name = p["name"]
            py_name = snake(name)
            header_block += (
                f"        if {py_name} is not None:\n"
                f"            extra_headers[{name!r}] = {py_name}\n"
            )

        call_kwargs = ["organization_id=organization_id"]
        if params_dict_items:
            call_kwargs.append("params=params")
        if body_arg:
            call_kwargs.append("json=body_json")
        call_kwargs.append("extra_headers=extra_headers or None")
        call_kwargs_str = ", ".join(call_kwargs)

        body_lines = []
        if params_build:
            body_lines.append(params_build.rstrip("\n"))
        if body_line:
            body_lines.append(body_line.rstrip("\n"))
        body_lines.append(header_block.rstrip("\n"))
        body_lines.append("        client = await get_client()")
        body_lines.append(
            f'        return await client.request("{method.upper()}", "{path}", {call_kwargs_str})'
        )

        tool_block = (
            f'    @mcp.tool(name="{func_name}", description={first_line[:4000]!r})\n'
            f"    async def {func_name}(\n"
            f"{sig},\n"
            f"    ) -> Any:\n"
            f'        """{docstring_desc}"""\n'
        )
        tool_block += "\n".join(body_lines) + "\n\n"
        lines.append(tool_block)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def main() -> int:
    if len(sys.argv) != 2:
        print("usage: generate_from_spec.py <spec.json>", file=sys.stderr)
        return 2

    raw_arg = sys.argv[1]
    resolved = os.path.realpath(raw_arg)
    if not os.path.isfile(resolved):
        print(f"error: {raw_arg!r} is not a file", file=sys.stderr)
        return 2
    with open(resolved, encoding="utf-8") as fh:
        spec = json.load(fh)
    spec_path = Path(resolved)

    # Walk chosen ops to find which schemas we need
    schema_seed: list[str] = []
    chosen_ops_by_tag: dict[str, list[tuple[str, str, dict]]] = defaultdict(list)
    for path, method in CHOSEN_ENDPOINTS:
        item = spec["paths"].get(path)
        if not item or method not in item:
            print(f"WARNING: missing endpoint {method.upper()} {path}", file=sys.stderr)
            continue
        op = item[method]
        tag = (op.get("tags") or ["Misc"])[0]
        chosen_ops_by_tag[tag].append((path, method, op))

        # Collect refs from this op
        for ref in _iter_refs(op):
            schema_seed.append(ref.rsplit("/", 1)[-1])

    needed = collect_referenced_schemas(spec, schema_seed)
    print(f"Chosen endpoints: {sum(len(v) for v in chosen_ops_by_tag.values())}", file=sys.stderr)
    print(f"Schemas to generate: {len(needed)}", file=sys.stderr)

    # Write models
    pkg_dir = Path(__file__).resolve().parent.parent / "src" / "threatlocker_mcp"
    models_path = pkg_dir / "models.py"
    models_path.write_text(generate_models(spec, needed), encoding="utf-8")
    print(f"Wrote {models_path}", file=sys.stderr)

    # Write tools per tag
    tools_dir = pkg_dir / "tools"
    tools_dir.mkdir(exist_ok=True)

    # Clear out old tool modules (everything but __init__.py). Log each unlink so
    # a developer who dropped a hand-edited file in tools/ sees it disappear.
    for f in tools_dir.glob("*.py"):
        if f.name != "__init__.py":
            print(f"Removing stale tool module {f.name}", file=sys.stderr)
            f.unlink()

    tag_modules: list[str] = []
    for tag, ops in sorted(chosen_ops_by_tag.items()):
        module_name = snake(tag)
        tag_modules.append((tag, module_name))
        out = generate_tools_module(tag, ops, needed)
        (tools_dir / f"{module_name}.py").write_text(out, encoding="utf-8")
        print(f"Wrote tools/{module_name}.py ({len(ops)} tools)", file=sys.stderr)

    # Write tools/__init__.py
    mod_names = [mod for _tag, mod in tag_modules]
    init_lines = [
        '"""Generated tool registry."""',
        "from fastmcp import FastMCP",
        "",
        "from . import (",
    ]
    for mod in mod_names:
        init_lines.append(f"    {mod},")
    init_lines += [
        ")",
        "",
        "",
        "def register_all(mcp: FastMCP) -> None:",
    ]
    for mod in mod_names:
        init_lines.append(f"    {mod}.register(mcp)")
    init_lines.append("")
    (tools_dir / "__init__.py").write_text("\n".join(init_lines), encoding="utf-8")
    print("Wrote tools/__init__.py", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
