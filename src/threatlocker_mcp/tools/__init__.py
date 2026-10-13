"""Generated tool registry."""

from fastmcp import FastMCP

from . import (
    action_log,
    application,
    approval_request,
    computer,
    computer_group,
    denied_activity,
    maintenance_mode,
    online_devices,
    organization,
    policy,
    report,
    system_audit,
    tag,
)


def register_all(mcp: FastMCP) -> None:
    action_log.register(mcp)
    application.register(mcp)
    approval_request.register(mcp)
    computer.register(mcp)
    computer_group.register(mcp)
    denied_activity.register(mcp)
    maintenance_mode.register(mcp)
    online_devices.register(mcp)
    organization.register(mcp)
    policy.register(mcp)
    report.register(mcp)
    system_audit.register(mcp)
    tag.register(mcp)
