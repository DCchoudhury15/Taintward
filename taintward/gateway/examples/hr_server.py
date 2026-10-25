"""A tiny HR MCP server used by the gateway tests and demo.

Tools:
  get_employee(employee_id)       internal lookup; returns an SSN and an AWS key
  list_departments()              internal, no sensitive data
  send_email(to, subject, body)   external; records exactly what it received

Every send_email call is appended to ``OUTBOX`` (in process) and, when the
``TAINTWARD_HR_OUTBOX`` env var names a file, written to it as one JSON line,
so tests can check what actually reached the external tool.

Run over stdio:  python -m taintward.gateway.examples.hr_server
"""

from __future__ import annotations

import json
import os

from mcp.server import MCPServer

SSN = "234-12-1234"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

OUTBOX: list[dict] = []

_EMPLOYEES = {
    "E100": {
        "employee_id": "E100",
        "department": "payroll",
        "ssn": SSN,
        "aws_access_key": AWS_KEY,
    },
}

mcp = MCPServer("hr")


@mcp.tool()
def get_employee(employee_id: str) -> dict:
    """Look up an employee record (internal HR system)."""
    rec = _EMPLOYEES.get(employee_id)
    if rec is None:
        return {"employee_id": employee_id, "found": False}
    return {**rec, "found": True}


@mcp.tool()
def list_departments() -> list[str]:
    """List department names."""
    return ["engineering", "payroll", "sales"]


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to an external address."""
    msg = {"to": to, "subject": subject, "body": body}
    OUTBOX.append(msg)
    path = os.environ.get("TAINTWARD_HR_OUTBOX")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(msg) + "\n")
    return "sent"


if __name__ == "__main__":
    mcp.run()
