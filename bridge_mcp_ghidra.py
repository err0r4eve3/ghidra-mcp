# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=1.2.0,<2",
# ]
# ///
"""
GhidraMCP Bridge — thin MCP↔HTTP multiplexer.

On startup: exposes list_instances + connect_instance.
On connect_instance: fetches /mcp/schema from the Ghidra server,
dynamically registers every tool. All dynamic tools are generic HTTP dispatchers.

Supports two transports to Ghidra:
  - UDS (Unix domain sockets) — preferred for local instances
  - TCP (HTTP) — fallback for headless/remote servers
"""

import argparse
import asyncio
import json
import logging
import os
import re
import socket
import time
import http.client
import inspect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.lowlevel.server import NotificationOptions

# ==========================================================================
# Configuration
# ==========================================================================

REQUEST_TIMEOUT = 30

# Per-endpoint timeout overrides for expensive operations
ENDPOINT_TIMEOUTS = {
    "rename_variables": 120,
    "batch_rename_variables": 120,
    "batch_set_comments": 120,
    "analyze_function_complete": 120,
    "batch_rename_function_components": 120,
    "batch_set_variable_types": 90,
    "analyze_data_region": 90,
    "batch_create_labels": 60,
    "batch_delete_labels": 60,
    "disassemble_bytes": 120,
    "bulk_fuzzy_match": 180,
    "find_similar_functions_fuzzy": 60,
    "import_file": 300,
    "run_ghidra_script": 1800,
    "run_script_inline": 1800,
    "decompile_function": 45,
    "set_function_prototype": 45,
    "rename_function": 45,
    "rename_function_by_address": 45,
    "consolidate_duplicate_types": 60,
    "batch_analyze_completeness": 120,
    "apply_function_documentation": 60,
    "default": 30,
}

DEFAULT_TCP_URL = "http://127.0.0.1:8089"

# Logging
LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global state
mcp = FastMCP("ghidra-mcp")

# Enable tools/list_changed notifications so clients re-fetch tools after dynamic registration
_orig_init_options = mcp._mcp_server.create_initialization_options


def _patched_init_options(**kwargs):
    return _orig_init_options(
        notification_options=NotificationOptions(tools_changed=True), **kwargs
    )


mcp._mcp_server.create_initialization_options = _patched_init_options

_active_socket: str | None = None  # UDS socket path
_active_tcp: str | None = None  # TCP base URL (e.g. "http://127.0.0.1:8089")
_transport_mode: str = "none"  # "uds", "tcp", or "none"
_connected_project: str | None = None  # Project name for auto-reconnect

SCHEMA_VERSION = "2.0"
SCHEMA_CAPABILITIES = {
    "catalog_metadata": True,
    "tool_filtering": True,
    "lazy_hydration_hints": True,
}
HIGH_RISK_CATEGORIES = {"debugger", "project", "server", "script", "process"}
TOOL_PROFILES = {
    "re": "Reverse engineering workflow tools",
}


# ==========================================================================
# UDS Transport
# ==========================================================================


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket."""

    def __init__(self, socket_path: str, timeout: int = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def get_socket_dir() -> Path:
    """Get the GhidraMCP socket runtime directory."""
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "ghidra-mcp"
    user = os.getenv("USER", "unknown")
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        return Path(tmpdir) / f"ghidra-mcp-{user}"
    return Path(f"/tmp/ghidra-mcp-{user}")


# Enhanced error classes
class GhidraConnectionError(Exception):
    """Raised when connection to Ghidra server fails"""

    pass


class GhidraAnalysisError(Exception):
    """Raised when Ghidra analysis operation fails"""

    pass


class GhidraValidationError(Exception):
    """Raised when input validation fails"""

    pass


# Input validation patterns
HEX_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")
SEGMENT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*:[0-9a-fA-F]+$")
# Handles space:0xHEX form (e.g., mem:0x1000, code:0xFF00).
# Must be checked BEFORE SEGMENT_ADDRESS_PATTERN because the 'x' in '0x' is not
# in [0-9a-fA-F], so the existing pattern rejects this form entirely.
SEGMENT_ADDR_WITH_0X_PATTERN = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_]*):0[xX]([0-9a-fA-F]+)$"
)
FUNCTION_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Running but owned by another user


def normalize_server_url(url: str) -> str:
    """Normalize server URL, accepting host:port inputs by adding http://."""
    if not url:
        return url
    url = url.strip()
    if "://" not in url:
        return f"http://{url}"
    return url


def validate_server_url(url: str) -> bool:
    """Validate that the server URL is safe to use."""
    try:
        normalized = normalize_server_url(url)
        parsed = urlparse(normalized)
        host = parsed.hostname
        if not host and parsed.path:
            reparsed = urlparse(normalize_server_url(parsed.path))
            host = reparsed.hostname
        return host in ("127.0.0.1", "localhost", "::1")
    except Exception:
        return False


def validate_hex_address(address: str) -> bool:
    """Validate that an address string looks like a valid hex address or segment:offset."""
    if not address:
        return False
    if SEGMENT_ADDR_WITH_0X_PATTERN.match(address):
        return True
    if SEGMENT_ADDRESS_PATTERN.match(address):
        return True
    return bool(HEX_ADDRESS_PATTERN.match(address))


def uds_request(
    socket_path: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Make an HTTP request over a Unix domain socket. Returns (body, status)."""
    conn = UnixHTTPConnection(socket_path, timeout=timeout)
    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        path = f"{path}?{urlencode(params)}"

    headers = {"Connection": "close"}
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        status = response.status
        return result, status
    finally:
        conn.close()


# ==========================================================================
# TCP Transport
# ==========================================================================


def tcp_request(
    base_url: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Make an HTTP request over TCP. Returns (body, status)."""
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)

    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        path = f"{path}?{urlencode(params)}"

    headers = {"Connection": "close"}
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        status = response.status
        return result, status
    finally:
        conn.close()


# ==========================================================================
# Unified request function
# ==========================================================================


def do_request(
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Route request to the active transport (UDS or TCP)."""
    if _transport_mode == "uds" and _active_socket:
        return uds_request(_active_socket, method, endpoint, params, json_data, timeout)
    elif _transport_mode == "tcp" and _active_tcp:
        return tcp_request(_active_tcp, method, endpoint, params, json_data, timeout)
    else:
        raise ConnectionError(
            "No Ghidra instance connected. Use connect_instance() first."
        )


# ==========================================================================
# Instance discovery
# ==========================================================================


def discover_instances() -> list[dict]:
    """Scan socket directory and query each live instance for info."""
    socket_dir = get_socket_dir()
    if not socket_dir.exists():
        return []

    instances = []
    for sock_file in sorted(socket_dir.glob("*.sock")):
        name = sock_file.stem  # ghidra-<pid>
        dash = name.rfind("-")
        if dash < 0:
            continue
        try:
            pid = int(name[dash + 1 :])
        except ValueError:
            continue

        if not is_pid_alive(pid):
            logger.debug(f"Cleaning up stale socket: {sock_file}")
            try:
                sock_file.unlink(missing_ok=True)
            except OSError:
                pass
            continue

        info: dict = {"socket": str(sock_file), "pid": pid}
        try:
            text, status = uds_request(
                str(sock_file), "GET", "/mcp/instance_info", timeout=5
            )
            if status == 200:
                info.update(_unwrap_response_data(text))
        except Exception as e:
            logger.debug(f"Could not query {sock_file}: {e}")

        instances.append(info)

    return instances


def _unwrap_response_data(text: str) -> dict:
    """Unwrap Response.ok() payloads while preserving plain JSON responses."""
    data = json.loads(text)
    if isinstance(data, dict) and "data" in data:
        return data["data"]
    return data


def discover_active_tcp_instance() -> dict | None:
    """Return the active TCP fallback connection as an instance-like record."""
    if _transport_mode != "tcp" or not _active_tcp:
        return None

    info: dict = {
        "transport": "tcp",
        "url": _active_tcp,
        "discovery": "active-tcp",
    }
    if _connected_project:
        info["project"] = _connected_project

    try:
        text, status = tcp_request(_active_tcp, "GET", "/mcp/instance_info", timeout=5)
        if status == 200:
            info.update(_unwrap_response_data(text))
            return info
    except Exception as e:
        logger.debug(f"Could not query TCP instance info for {_active_tcp}: {e}")

    try:
        text, status = tcp_request(_active_tcp, "GET", "/list_open_programs", timeout=5)
        if status == 200:
            data = _unwrap_response_data(text)
            if isinstance(data, dict):
                for key in ("programs", "count", "current_program"):
                    if key in data:
                        info[key] = data[key]
    except Exception as e:
        logger.debug(
            f"Could not query open programs for active TCP instance {_active_tcp}: {e}"
        )

    return info


# ==========================================================================
# HTTP dispatch
# ==========================================================================


def get_timeout(endpoint: str, payload: dict | None = None) -> int:
    """Get timeout for an endpoint, with dynamic scaling for batch ops."""
    name = endpoint.strip("/").split("/")[-1]
    base = ENDPOINT_TIMEOUTS.get(name, ENDPOINT_TIMEOUTS["default"])

    if not payload:
        return base

    if name in {"rename_variables", "batch_rename_variables"}:
        count = len(payload.get("variable_renames", {}))
        return min(base + count * 38, 600)

    if name == "batch_set_comments":
        count = len(payload.get("decompiler_comments", []))
        count += len(payload.get("disassembly_comments", []))
        count += 1 if payload.get("plate_comment") else 0
        return min(base + count * 8, 600)

    return base


def _try_reconnect() -> bool:
    """Try to reconnect to the previously connected project after Ghidra restarts.

    Scans for UDS instances matching _connected_project. If found, updates the
    active socket and re-fetches the schema. Returns True if reconnected.
    """
    global _active_socket, _active_tcp, _transport_mode

    if not _connected_project:
        return False

    instances = discover_instances()
    for inst in instances:
        if inst.get("project", "") == _connected_project:
            _active_socket = inst["socket"]
            _active_tcp = None
            _transport_mode = "uds"
            try:
                _fetch_and_register_schema()
                logger.info(
                    f"Reconnected to project '{_connected_project}' via {inst['socket']}"
                )
                return True
            except Exception as e:
                logger.warning(f"Reconnect schema fetch failed: {e}")
                return False

    # Exact match failed, try substring
    for inst in instances:
        if _connected_project.lower() in inst.get("project", "").lower():
            _active_socket = inst["socket"]
            _active_tcp = None
            _transport_mode = "uds"
            try:
                _fetch_and_register_schema()
                logger.info(
                    f"Reconnected to project '{inst.get('project')}' via {inst['socket']}"
                )
                return True
            except Exception as e:
                logger.warning(f"Reconnect schema fetch failed: {e}")
                return False

    return False


def _ensure_connected() -> str | None:
    """Check connection and attempt reconnect if needed. Returns error string or None."""
    if _transport_mode == "none":
        if _connected_project:
            if _try_reconnect():
                return None
            return (
                f"Ghidra instance for project '{_connected_project}' is not running. "
                "Start Ghidra and open the project, then retry."
            )
        return "No Ghidra instance connected. Use connect_instance() first."
    return None


def sanitize_address(address: str) -> str:
    """Normalize address format for Ghidra AddressFactory.

    Handles:
    - space:0xHEX  -> space:HEX   (strip 0x from offset; AddressFactory rejects 0x after colon)
    - SPACE:HEX    -> space:HEX   (lowercase space name; AddressFactory is case-sensitive)
    - 0xHEX        -> 0xhex       (lowercase)
    - HEX          -> 0xHEX       (add 0x prefix)
    """
    if not address:
        return address
    address = address.strip()

    # Step 1: handle space:0xHEX form (checked first — 'x' not in [0-9a-fA-F])
    m = SEGMENT_ADDR_WITH_0X_PATTERN.match(address)
    if m:
        # Lowercase space name; preserve offset case (AddressFactory handles hex case)
        return f"{m.group(1).lower()}:{m.group(2)}"

    # Step 2: normalize valid space:HEX form (lowercase space name only)
    if SEGMENT_ADDRESS_PATTERN.match(address):
        space, offset = address.split(":", 1)
        return f"{space.lower()}:{offset}"

    # Step 3: plain hex normalization (unchanged logic)
    if not address.startswith(("0x", "0X")):
        address = "0x" + address
    return address.lower()


def dispatch_get(endpoint: str, params: dict | None = None, retries: int = 3) -> str:
    """GET request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

    timeout = get_timeout(endpoint)
    for attempt in range(retries):
        try:
            text, status = do_request("GET", endpoint, params=params, timeout=timeout)
            if status == 200:
                return text
            if status >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except (ConnectionError, OSError) as e:
            # Connection lost — try reconnect once, then retry
            if attempt == 0 and _try_reconnect():
                continue
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})
        except Exception as e:
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


def dispatch_post(endpoint: str, data: dict, retries: int = 3) -> str:
    """POST JSON request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

    timeout = get_timeout(endpoint, data)
    for attempt in range(retries):
        try:
            text, status = do_request("POST", endpoint, json_data=data, timeout=timeout)
            if status == 200:
                return text.strip()
            if status >= 500 and attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except (ConnectionError, OSError) as e:
            # Connection lost — try reconnect once, then retry
            if attempt == 0 and _try_reconnect():
                continue
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": str(e)})
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


# ==========================================================================
# Schema parsing — converts upstream /mcp/schema to internal tool defs
# ==========================================================================

# JSON type → Python type mapping
_TYPE_MAP = {
    "string": str,
    "json": str,
    "integer": int,
    "boolean": bool,
    "number": float,
    "object": dict,
    "array": list,
    "any": str,
    "address": str,
}

STATIC_TOOL_METADATA = {
    "list_instances": {
        "endpoint": "/list_instances",
        "http_method": "GET",
        "description": "List known Ghidra instances and the active connection.",
        "category": "utility",
        "category_description": "Bridge control plane",
        "title": "List Instances",
        "tags": ["discovery", "control-plane"],
        "side_effect": "read",
        "read_only_hint": True,
        "approval_default": "never",
        "visibility": "model",
        "profile_tags": [],
        "openai_summary": "Use this when you need to discover running Ghidra instances.",
        "surface": "tool",
    },
    "connect_instance": {
        "endpoint": "/connect_instance",
        "http_method": "POST",
        "description": "Connect the bridge to a specific Ghidra instance.",
        "category": "utility",
        "category_description": "Bridge control plane",
        "title": "Connect Instance",
        "tags": ["control-plane", "connection"],
        "side_effect": "write",
        "read_only_hint": False,
        "approval_default": "required",
        "visibility": "model",
        "profile_tags": [],
        "openai_summary": "Use this when you need to connect the bridge to a Ghidra instance.",
        "surface": "tool",
    },
    "list_tool_groups": {
        "endpoint": "/list_tool_groups",
        "http_method": "GET",
        "description": "List available tool groups and their loaded status.",
        "category": "utility",
        "category_description": "Bridge control plane",
        "title": "List Tool Groups",
        "tags": ["control-plane", "group-loading"],
        "side_effect": "read",
        "read_only_hint": True,
        "approval_default": "never",
        "visibility": "model",
        "profile_tags": [],
        "openai_summary": "Use this when you need to inspect available tool groups before loading more tools.",
        "surface": "tool",
    },
    "load_tool_group": {
        "endpoint": "/load_tool_group",
        "http_method": "POST",
        "description": "Load a tool group into the visible MCP tool list.",
        "category": "utility",
        "category_description": "Bridge control plane",
        "title": "Load Tool Group",
        "tags": ["control-plane", "group-loading"],
        "side_effect": "write",
        "read_only_hint": False,
        "approval_default": "required",
        "visibility": "model",
        "profile_tags": [],
        "openai_summary": "Use this when you need to expose an additional tool group to the model.",
        "surface": "tool",
    },
    "unload_tool_group": {
        "endpoint": "/unload_tool_group",
        "http_method": "POST",
        "description": "Unload a tool group from the visible MCP tool list.",
        "category": "utility",
        "category_description": "Bridge control plane",
        "title": "Unload Tool Group",
        "tags": ["control-plane", "group-loading"],
        "side_effect": "write",
        "read_only_hint": False,
        "approval_default": "required",
        "visibility": "model",
        "profile_tags": [],
        "openai_summary": "Use this when you need to hide a previously loaded tool group.",
        "surface": "tool",
    },
    "check_tools": {
        "endpoint": "/check_tools",
        "http_method": "GET",
        "description": "Check whether specific tools are callable right now.",
        "category": "utility",
        "category_description": "Bridge control plane",
        "title": "Check Tools",
        "tags": ["control-plane", "validation"],
        "side_effect": "read",
        "read_only_hint": True,
        "approval_default": "never",
        "visibility": "model",
        "profile_tags": [],
        "openai_summary": "Use this when you need to verify whether a tool is currently callable.",
        "surface": "tool",
    },
    "import_file": {
        "endpoint": "/import_file",
        "http_method": "POST",
        "description": "Import a binary file into the current Ghidra project.",
        "category": "project",
        "category_description": "Project lifecycle management",
        "title": "Import File",
        "tags": ["project", "import"],
        "side_effect": "write",
        "read_only_hint": False,
        "approval_default": "required",
        "visibility": "model",
        "profile_tags": [],
        "openai_summary": "Use this when you need to import a new file into the connected Ghidra project.",
        "surface": "tool",
    },
}
ALWAYS_VISIBLE_TOOLS = {
    "list_instances",
    "connect_instance",
    "list_tool_groups",
    "load_tool_group",
    "unload_tool_group",
    "check_tools",
}


def _normalize_method(method: str | None) -> str:
    return (method or "GET").strip().upper()


def _normalize_category(category: str | None) -> str:
    return (category or "unknown").strip().lower()


def _derive_side_effect(method: str, category: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip().lower()
    if method == "POST":
        return "write"
    if category == "debugger":
        return "read"
    return "read"


def _derive_read_only_hint(side_effect: str, explicit: Any = None) -> bool:
    if explicit is not None and explicit != "":
        if isinstance(explicit, bool):
            return explicit
        return str(explicit).strip().lower() == "true"
    return side_effect == "read"


def _derive_approval_default(
    method: str,
    category: str,
    explicit: str | None = None,
) -> str:
    if explicit:
        return explicit.strip().lower()
    if category in HIGH_RISK_CATEGORIES:
        return "required"
    return "required" if method == "POST" else "never"


def _derive_visibility(explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip().lower()
    return "model"


def _derive_title(path: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip()
    words = path.lstrip("/").replace("/", " ").replace("_", " ").split()
    return " ".join(word[:1].upper() + word[1:] for word in words)


def _derive_tags(
    category: str,
    method: str,
    side_effect: str,
    explicit: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    values: list[str] = []
    for value in [category, method.lower(), side_effect, *(explicit or [])]:
        normalized = str(value).strip().lower()
        if normalized and normalized not in values:
            values.append(normalized)
    return values


def _derive_profile_tags(
    category: str,
    explicit: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    values: list[str] = []
    for value in explicit or []:
        normalized = str(value).strip().lower()
        if normalized and normalized not in values:
            values.append(normalized)
    if not values and category not in HIGH_RISK_CATEGORIES:
        values.append("re")
    return values


def _derive_openai_summary(
    description: str,
    title: str,
    explicit: str | None = None,
) -> str:
    if explicit:
        return explicit.strip()
    if description:
        return f"Use this when you need to {description[:1].lower()}{description[1:]}"
    return f"Use this when you need {title.lower()}."


@dataclass(frozen=True)
class ToolCatalogEntry:
    name: str
    endpoint: str
    http_method: str
    description: str
    category: str
    category_description: str
    input_schema: dict[str, Any]
    title: str
    tags: tuple[str, ...]
    side_effect: str
    read_only_hint: bool
    approval_default: str
    visibility: str
    profile_tags: tuple[str, ...]
    openai_summary: str
    surface: str
    origin: str = "dynamic"


@dataclass(frozen=True)
class ToolPolicy:
    profiles: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    read_only_only: bool = False
    approval_mode: str = "never"
    allowlist: set[str] = field(default_factory=set)

    def matches(self, entry: ToolCatalogEntry) -> bool:
        if entry.visibility != "model":
            return False
        if self.allowlist and entry.name not in self.allowlist:
            return False
        if self.profiles and not (self.profiles & set(entry.profile_tags)):
            return False
        if self.categories and entry.category not in self.categories:
            return False
        if self.tags and not (self.tags & set(entry.tags)):
            return False
        if self.read_only_only and not entry.read_only_hint:
            return False
        if self.approval_mode == "never" and entry.approval_default != "never":
            return False
        if self.approval_mode == "required" and entry.approval_default != "required":
            return False
        return True


@dataclass
class ToolCatalog:
    entries: dict[str, ToolCatalogEntry]
    dynamic_names: set[str] = field(default_factory=set)
    static_names: set[str] = field(default_factory=set)
    schema_version: str = SCHEMA_VERSION
    capabilities: dict[str, Any] = field(default_factory=lambda: dict(SCHEMA_CAPABILITIES))

    @classmethod
    def from_schema(
        cls,
        raw: dict,
        static_catalog: dict[str, ToolCatalogEntry] | None = None,
    ):
        parsed = _parse_schema(raw)
        entries: dict[str, ToolCatalogEntry] = {}
        dynamic_names: set[str] = set()
        for tool_def in parsed:
            entry = _catalog_entry_from_tool_def(tool_def, origin="dynamic")
            entries[entry.name] = entry
            dynamic_names.add(entry.name)

        static_names: set[str] = set()
        if static_catalog:
            for name, entry in static_catalog.items():
                entries[name] = entry
                static_names.add(name)

        return cls(
            entries=entries,
            dynamic_names=dynamic_names,
            static_names=static_names,
            schema_version=raw.get("schema_version", SCHEMA_VERSION),
            capabilities=raw.get("capabilities", dict(SCHEMA_CAPABILITIES)),
        )

    def filter(
        self,
        policy: ToolPolicy,
        *,
        include_dynamic: bool = True,
        include_static: bool = True,
    ) -> list[str]:
        names: list[str] = []
        for name in sorted(self.entries):
            if name in self.dynamic_names and not include_dynamic:
                continue
            if name in self.static_names and not include_static:
                continue
            if policy.matches(self.entries[name]):
                names.append(name)
        return names


def _catalog_entry_from_tool_def(tool_def: dict, origin: str) -> ToolCatalogEntry:
    return ToolCatalogEntry(
        name=tool_def["name"],
        endpoint=tool_def["endpoint"],
        http_method=_normalize_method(tool_def.get("http_method")),
        description=tool_def.get("description", ""),
        category=_normalize_category(tool_def.get("category")),
        category_description=tool_def.get("category_description", ""),
        input_schema=tool_def.get("input_schema", {"type": "object", "properties": {}}),
        title=tool_def.get("title", _derive_title(tool_def["endpoint"])),
        tags=tuple(tool_def.get("tags", [])),
        side_effect=tool_def.get("side_effect", "read"),
        read_only_hint=bool(tool_def.get("read_only_hint", True)),
        approval_default=tool_def.get("approval_default", "never"),
        visibility=tool_def.get("visibility", "model"),
        profile_tags=tuple(tool_def.get("profile_tags", [])),
        openai_summary=tool_def.get("openai_summary", tool_def.get("description", "")),
        surface=tool_def.get("surface", "tool"),
        origin=origin,
    )


def get_static_tool_catalog() -> dict[str, ToolCatalogEntry]:
    return {
        name: _catalog_entry_from_tool_def(
            {
                "name": name,
                **meta,
                "input_schema": {"type": "object", "properties": {}, "required": []},
            },
            origin="static",
        )
        for name, meta in STATIC_TOOL_METADATA.items()
    }


class HydrationCache:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._raw_schema: dict | None = None
        self._catalog: ToolCatalog | None = None
        self._fingerprint: tuple | None = None

    async def get_catalog_async(self, force_refresh: bool = False) -> ToolCatalog:
        async with self._lock:
            if self._catalog is not None and not force_refresh:
                return self._catalog
            raw = _fetch_remote_schema()
            fingerprint = self._fingerprint_for(raw)
            if (
                not force_refresh
                and self._catalog is not None
                and self._fingerprint == fingerprint
            ):
                return self._catalog
            self._raw_schema = raw
            self._fingerprint = fingerprint
            self._catalog = ToolCatalog.from_schema(raw, get_static_tool_catalog())
            return self._catalog

    def get_catalog(self, force_refresh: bool = False) -> ToolCatalog:
        if self._catalog is not None and not force_refresh:
            return self._catalog
        raw = _fetch_remote_schema()
        fingerprint = self._fingerprint_for(raw)
        if (
            not force_refresh
            and self._catalog is not None
            and self._fingerprint == fingerprint
        ):
            return self._catalog
        self._raw_schema = raw
        self._fingerprint = fingerprint
        self._catalog = ToolCatalog.from_schema(raw, get_static_tool_catalog())
        return self._catalog

    @staticmethod
    def _fingerprint_for(raw: dict) -> tuple:
        return (
            raw.get("schema_version", SCHEMA_VERSION),
            raw.get("count", len(raw.get("tools", []))),
            tuple(sorted(tool.get("path", "") for tool in raw.get("tools", []))),
        )

    def update(self, raw: dict):
        self._raw_schema = raw
        self._fingerprint = self._fingerprint_for(raw)
        self._catalog = ToolCatalog.from_schema(raw, get_static_tool_catalog())
        return self._catalog


def _fetch_remote_schema() -> dict:
    text, status = do_request("GET", "/mcp/schema", timeout=10)
    if status != 200:
        raise RuntimeError(f"Failed to fetch schema: HTTP {status}")
    return json.loads(text)


def _parse_schema(raw: dict) -> list[dict]:
    """Convert upstream AnnotationScanner schema to internal tool defs."""
    tool_defs = []
    for tool in raw.get("tools", []):
        path = tool["path"]
        name = path.lstrip("/")
        method = _normalize_method(tool.get("method", "GET"))
        category = _normalize_category(tool.get("category", "unknown"))
        params = tool.get("params", [])

        properties = {}
        required = []
        for p in params:
            pdef: dict = {"type": p.get("type", "string")}
            if p.get("description"):
                pdef["description"] = p["description"]
            if "default" in p and p["default"] is not None:
                pdef["default"] = p["default"]
            if p.get("param_type"):
                pdef["paramType"] = p["param_type"]
            properties[p["name"]] = pdef
            if p.get("required", False):
                required.append(p["name"])

        title = tool.get("title", _derive_title(path))
        side_effect = _derive_side_effect(method, category, tool.get("side_effect"))
        tool_defs.append(
            {
                "name": name,
                "endpoint": path,
                "http_method": method,
                "description": tool.get("description", ""),
                "category": category,
                "category_description": tool.get("category_description", ""),
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
                "title": title,
                "tags": _derive_tags(category, method, side_effect, tool.get("tags")),
                "side_effect": side_effect,
                "read_only_hint": _derive_read_only_hint(
                    side_effect, tool.get("read_only_hint")
                ),
                "approval_default": _derive_approval_default(
                    method, category, tool.get("approval_default")
                ),
                "visibility": _derive_visibility(tool.get("visibility")),
                "profile_tags": _derive_profile_tags(
                    category, tool.get("profile_tags")
                ),
                "openai_summary": _derive_openai_summary(
                    tool.get("description", ""),
                    title,
                    tool.get("openai_summary"),
                ),
                "surface": tool.get("surface", "tool"),
            }
        )

    return tool_defs


# ==========================================================================
# Dynamic tool registration from /mcp/schema
# ==========================================================================

# Static tool names that should not be overwritten by dynamic registration
STATIC_TOOL_NAMES = {
    "list_instances",
    "connect_instance",
    "list_tool_groups",
    "load_tool_group",
    "unload_tool_group",
    "check_tools",
    "import_file",
}

_dynamic_tool_names: list[str] = []
_full_schema: list[dict] = []  # Complete parsed schema
_loaded_groups: set[str] = set()
_tool_policy = ToolPolicy()
_hydration_cache = HydrationCache()

# Core groups always loaded on connect (essential for basic RE workflow)
CORE_GROUPS = {"listing", "function", "program"}

# CLI-configurable: --lazy keeps only default groups, otherwise load all
_lazy_mode = True
_default_groups: set[str] = CORE_GROUPS


def _policy_for(policy: ToolPolicy | None) -> ToolPolicy:
    return policy if policy is not None else _tool_policy


def _tool_is_visible(tool_def: dict, policy: ToolPolicy) -> bool:
    return policy.matches(_catalog_entry_from_tool_def(tool_def, origin="dynamic"))


def _register_static_tool(name: str):
    tool_manager = getattr(mcp, "_tool_manager", None)
    tools = getattr(tool_manager, "_tools", None)
    if not isinstance(tools, dict):
        return
    if name in tools:
        return
    func = globals().get(name)
    entry = get_static_tool_catalog().get(name)
    if callable(func) and entry is not None:
        mcp.tool(name=name, description=entry.openai_summary)(func)


def _apply_static_tool_policy(policy: ToolPolicy | None = None):
    effective_policy = _policy_for(policy)
    tool_manager = getattr(mcp, "_tool_manager", None)
    tools = getattr(tool_manager, "_tools", None)
    if not isinstance(tools, dict):
        return
    static_catalog = get_static_tool_catalog()
    allowed = set(ALWAYS_VISIBLE_TOOLS)
    for name, entry in static_catalog.items():
        if name in ALWAYS_VISIBLE_TOOLS:
            continue
        if effective_policy.matches(entry):
            allowed.add(name)

    for name in list(STATIC_TOOL_NAMES):
        if name in allowed:
            _register_static_tool(name)
        else:
            tools.pop(name, None)


def _build_tool_function(endpoint: str, http_method: str, params_schema: dict):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    properties = params_schema.get("properties", {})
    required = set(params_schema.get("required", []))

    def handler(**kwargs):
        # Sanitize address parameters before dispatch
        for pname, pdef in properties.items():
            if (
                pdef.get("paramType") == "address"
                and pname in kwargs
                and kwargs[pname] is not None
            ):
                kwargs[pname] = sanitize_address(str(kwargs[pname]))
        filtered = {k: v for k, v in kwargs.items() if v is not None}
        if http_method == "GET":
            str_params = {k: str(v) for k, v in filtered.items()}
            return dispatch_get(endpoint, params=str_params if str_params else None)
        else:
            return dispatch_post(endpoint, data=filtered)

    # Build function signature with proper types and defaults
    # Params with defaults must come after params without defaults
    required_params = []
    optional_params = []
    for pname, pdef in properties.items():
        json_type = pdef.get("type", "string")
        py_type = _TYPE_MAP.get(json_type, str)
        default = pdef.get("default", inspect.Parameter.empty)
        if pname not in required and default is inspect.Parameter.empty:
            default = None
            py_type = py_type | None if py_type != str else str | None

        param = inspect.Parameter(
            pname, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=py_type
        )
        if default is inspect.Parameter.empty:
            required_params.append(param)
        else:
            optional_params.append(param)

    sig_params = required_params + optional_params
    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__annotations__ = {p.name: p.annotation for p in sig_params}
    handler.__annotations__["return"] = str

    return handler


def _register_tool_def(tool_def: dict) -> bool:
    """Register a single tool from a schema definition. Returns True if registered."""
    name = tool_def["name"]
    if name in STATIC_TOOL_NAMES:
        return False  # Don't overwrite static tools
    description = tool_def.get("openai_summary") or tool_def.get("description", "")
    endpoint = tool_def["endpoint"]
    http_method = tool_def.get("http_method", "GET")
    input_schema = tool_def.get("input_schema", {"type": "object", "properties": {}})

    handler = _build_tool_function(endpoint, http_method, input_schema)
    handler.__name__ = name
    handler.__doc__ = description

    mcp.tool(name=name, description=description)(handler)
    _dynamic_tool_names.append(name)
    return True


def register_tools_from_schema(
    schema: list[dict], groups: set[str] | None = None, policy: ToolPolicy | None = None
) -> int:
    """Register MCP tools from parsed schema.

    Args:
        schema: List of parsed tool definitions.
        groups: If provided, only register tools in these groups. None = register all.
        policy: Additional visibility filter for OpenAI-first routing.

    Returns: count of registered tools.
    """
    global _dynamic_tool_names, _full_schema, _loaded_groups
    effective_policy = _policy_for(policy)

    # Remove previously registered dynamic tools
    for name in _dynamic_tool_names:
        try:
            mcp._tool_manager._tools.pop(name, None)
        except Exception:
            pass
    _dynamic_tool_names.clear()
    _loaded_groups.clear()

    # Store full schema for lazy loading
    _full_schema = schema

    count = 0
    for tool_def in schema:
        category = tool_def.get("category", "unknown")
        if groups is not None and category not in groups:
            continue
        if not _tool_is_visible(tool_def, effective_policy):
            continue
        if _register_tool_def(tool_def):
            _loaded_groups.add(category)
            count += 1

    _apply_static_tool_policy(effective_policy)

    return count


def _load_group(group_name: str) -> list[str]:
    """Load tools for a specific group from cached schema. Returns list of newly loaded tool names."""
    loaded_names: list[str] = []
    effective_policy = _policy_for(None)
    for tool_def in _full_schema:
        if tool_def.get("category") != group_name:
            continue
        name = tool_def["name"]
        if name in _dynamic_tool_names:
            continue  # Already loaded
        if not _tool_is_visible(tool_def, effective_policy):
            continue
        _register_tool_def(tool_def)
        loaded_names.append(name)
    if loaded_names:
        _loaded_groups.add(group_name)
    return loaded_names


def _unload_group(group_name: str) -> int:
    """Unload tools for a specific group. Returns count of removed tools."""
    if group_name in _default_groups:
        return 0  # Default groups can't be unloaded

    to_remove = []
    for tool_def in _full_schema:
        if tool_def.get("category") == group_name:
            name = tool_def["name"]
            if name in _dynamic_tool_names:
                to_remove.append(name)

    for name in to_remove:
        try:
            mcp._tool_manager._tools.pop(name, None)
            _dynamic_tool_names.remove(name)
        except Exception:
            pass

    if to_remove:
        _loaded_groups.discard(group_name)
    return len(to_remove)


def _get_group_info() -> list[dict]:
    """Get info about all tool groups from cached schema."""
    groups: dict[str, list[str]] = {}
    visible_groups: dict[str, list[str]] = {}
    descriptions: dict[str, str] = {}
    effective_policy = _policy_for(None)
    for tool_def in _full_schema:
        cat = tool_def.get("category", "unknown")
        groups.setdefault(cat, []).append(tool_def["name"])
        if _tool_is_visible(tool_def, effective_policy):
            visible_groups.setdefault(cat, []).append(tool_def["name"])
        if cat not in descriptions and tool_def.get("category_description"):
            descriptions[cat] = tool_def["category_description"]

    result = []
    for name, tools in sorted(groups.items()):
        visible = sorted(visible_groups.get(name, []))
        info: dict = {
            "group": name,
            "tool_count": len(tools),
            "visible_tool_count": len(visible),
            "loaded": name in _loaded_groups,
            "default": name in _default_groups,
        }
        if name in descriptions:
            info["description"] = descriptions[name]
        if visible and len(visible) != len(tools):
            info["hidden_tool_count"] = len(tools) - len(visible)
        info["tools"] = visible
        result.append(info)
    return result


def _fetch_and_register_schema(load_all: bool = False) -> int:
    """Fetch /mcp/schema from connected instance and register tools.

    Args:
        load_all: If True, register all tools. If False, only default groups.

    Returns: count of registered tools.
    """
    if not load_all:
        load_all = not _lazy_mode
    raw = _fetch_remote_schema()
    _hydration_cache.update(raw)
    schema = _parse_schema(raw)
    groups = None if load_all else _default_groups
    return register_tools_from_schema(schema, groups=groups, policy=_tool_policy)


def export_allowed_tools(policy: ToolPolicy) -> list[str]:
    catalog = _hydration_cache.get_catalog()
    return catalog.filter(policy)


async def _notify_tools_changed(ctx: Context | None) -> None:
    """Send tools/list_changed notification if context is available."""
    if ctx is not None and ctx._request_context is not None:
        await ctx.request_context.session.send_tool_list_changed()


# ==========================================================================
# Static MCP tools (always available)
# ==========================================================================


@mcp.tool()
def list_instances() -> str:
    """
    List known Ghidra instances from UDS discovery and the active TCP fallback.

    Returns JSON with each instance's project name, PID, open programs, and
    socket path or TCP URL. Also shows which instance is currently connected.
    """
    instances = discover_instances()
    tcp_instance = discover_active_tcp_instance()
    if tcp_instance:
        instances.append(tcp_instance)

    if not instances:
        return json.dumps(
            {"instances": [], "note": "No running Ghidra instances found."}
        )

    for inst in instances:
        if inst.get("transport") == "tcp":
            inst["connected"] = (
                _transport_mode == "tcp" and inst.get("url") == _active_tcp
            )
        else:
            inst["connected"] = inst["socket"] == _active_socket

    return json.dumps({"instances": instances}, indent=2)


@mcp.tool()
async def connect_instance(project: str, ctx: Context | None = None) -> str:
    """
    Switch the MCP bridge to a different Ghidra instance by project name.

    After connecting, fetches the tool schema from the instance and dynamically
    registers all available tools. Use list_instances() first to see available instances.

    Args:
        project: Project name (or substring) to connect to
    """
    global _active_socket, _active_tcp, _transport_mode, _connected_project

    instances = discover_instances()

    # Try UDS instances first
    if instances:
        match = None
        for inst in instances:
            if inst.get("project", "") == project:
                match = inst
                break
        if not match:
            for inst in instances:
                if project.lower() in inst.get("project", "").lower():
                    match = inst
                    break
        if match:
            _active_socket = match["socket"]
            _active_tcp = None
            _transport_mode = "uds"
            _connected_project = match.get("project")

            try:
                count = _fetch_and_register_schema()
                total = len(_full_schema)
                await _notify_tools_changed(ctx)
                return json.dumps(
                    {
                        "connected": True,
                        "transport": "uds",
                        "project": _connected_project,
                        "socket": match["socket"],
                        "pid": match.get("pid"),
                        "tools_registered": count,
                        "tools_total": total,
                        "loaded_groups": sorted(_loaded_groups),
                        "note": f"Loaded {count}/{total} tools (core groups). Use load_tool_group() for more.",
                    }
                )
            except Exception as e:
                return json.dumps(
                    {"error": f"Schema fetch failed: {e}", "socket": _active_socket}
                )

    # Try TCP fallback
    tcp_url = normalize_server_url(os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL))
    if not validate_server_url(tcp_url):
        return json.dumps(
            {
                "error": f"Refusing to connect to non-local URL: {tcp_url}. Only 127.0.0.1, localhost, and ::1 are allowed."
            }
        )
    try:
        _active_tcp = tcp_url
        _active_socket = None
        _transport_mode = "tcp"
        count = _fetch_and_register_schema()
        total = len(_full_schema)
        await _notify_tools_changed(ctx)
        return json.dumps(
            {
                "connected": True,
                "transport": "tcp",
                "url": tcp_url,
                "tools_registered": count,
                "tools_total": total,
                "loaded_groups": sorted(_loaded_groups),
            }
        )
    except Exception as e:
        _transport_mode = "none"
        _active_tcp = None
        available = [inst.get("project", "unknown") for inst in instances]
        return json.dumps(
            {
                "error": f"No instance matching '{project}' (UDS: {len(instances)} found, TCP {tcp_url}: {e})",
                "available": available,
            }
        )


@mcp.tool()
def list_tool_groups() -> str:
    """
    List all available tool groups with their tool counts and loaded status.

    Returns each category with: tool count, loaded status, and tool names.
    Use load_tool_group(group) to load a group's tools.
    """
    if not _full_schema:
        return json.dumps(
            {"error": "No instance connected. Use connect_instance() first."}
        )
    groups = _get_group_info()
    return json.dumps({"groups": groups, "total_tools": len(_full_schema)}, indent=2)


@mcp.tool()
async def load_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Load all tools in a category. Accepts a category name or "all" to load everything.

    Use list_tool_groups() to see available categories.

    Args:
        group: Category name (e.g. "function", "datatype") or "all"
    """
    if not _full_schema:
        return json.dumps(
            {"error": "No instance connected. Use connect_instance() first."}
        )

    if group == "all":
        # Load all unloaded groups
        all_groups = {td.get("category", "unknown") for td in _full_schema}
        all_loaded: list[str] = []
        for g in sorted(all_groups):
            all_loaded.extend(_load_group(g))
        if all_loaded:
            await _notify_tools_changed(ctx)
        return json.dumps(
            {
                "loaded": "all",
                "new_tools": len(all_loaded),
                "new_tool_names": sorted(all_loaded),
                "total_loaded": len(_dynamic_tool_names),
            }
        )

    loaded_names = _load_group(group)
    if not loaded_names:
        available = sorted({td.get("category", "unknown") for td in _full_schema})
        if group in _loaded_groups:
            # Already loaded — return the tool names so the agent knows what's callable
            already = sorted(
                td["name"] for td in _full_schema if td.get("category") == group
            )
            return json.dumps(
                {
                    "message": f"Group '{group}' is already loaded.",
                    "tools": already,
                    "loaded_groups": sorted(_loaded_groups),
                }
            )
        return json.dumps(
            {
                "error": f"No tools found for group '{group}'",
                "available_groups": available,
            }
        )

    await _notify_tools_changed(ctx)
    return json.dumps(
        {
            "loaded": group,
            "new_tools": len(loaded_names),
            "tools": sorted(loaded_names),
            "total_loaded": len(_dynamic_tool_names),
            "loaded_groups": sorted(_loaded_groups),
        }
    )


@mcp.tool()
async def unload_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Unload all tools in a category. Default groups are protected from unloading.

    Args:
        group: Category name to unload
    """
    if group in _default_groups:
        return json.dumps(
            {
                "error": f"Cannot unload default group '{group}'",
                "default_groups": sorted(_default_groups),
            }
        )

    removed = _unload_group(group)
    if removed == 0:
        return json.dumps(
            {"message": f"Group '{group}' is not loaded or has no tools."}
        )

    await _notify_tools_changed(ctx)
    return json.dumps(
        {
            "unloaded": group,
            "removed_tools": removed,
            "total_loaded": len(_dynamic_tool_names),
            "loaded_groups": sorted(_loaded_groups),
        }
    )


@mcp.tool()
async def check_tools(tools: str) -> str:
    """
    Check if specific tools are callable right now. Returns status for each tool:
    "callable", "not_loaded" (exists but group not loaded), or "not_found" (doesn't exist).

    Args:
        tools: Comma-separated tool names, e.g. "rename_or_label,batch_set_comments,analyze_function_completeness"
    """
    tool_names = [t.strip() for t in tools.split(",") if t.strip()]
    if not tool_names:
        return json.dumps({"error": "Provide comma-separated tool names"})

    # Build lookup of all known tools -> their group
    all_known: dict[str, str] = {}
    for td in _full_schema:
        all_known[td["name"]] = td.get("category", "unknown")

    # Check each tool
    results: dict[str, dict] = {}
    for name in tool_names:
        if name in STATIC_TOOL_NAMES:
            results[name] = {"status": "callable", "type": "static"}
        elif name in _dynamic_tool_names:
            results[name] = {
                "status": "callable",
                "group": all_known.get(name, "unknown"),
            }
        elif name in all_known:
            group = all_known[name]
            results[name] = {
                "status": "not_loaded",
                "group": group,
                "fix": f'load_tool_group("{group}")',
            }
        else:
            results[name] = {"status": "not_found"}

    callable_count = sum(1 for r in results.values() if r["status"] == "callable")
    return json.dumps(
        {
            "results": results,
            "summary": f"{callable_count}/{len(tool_names)} callable",
        }
    )


@mcp.tool()
async def import_file(
    file_path: str,
    project_folder: str = "/",
    language: str | None = None,
    compiler_spec: str | None = None,
    auto_analyze: bool = True,
    ctx: Context | None = None,
) -> str:
    """
    Import a binary file from disk into the current Ghidra project.

    Imports the file, opens it in the CodeBrowser, and optionally starts auto-analysis.
    When analysis is enabled, sends a log notification when analysis completes.

    For raw firmware binaries, specify language (e.g. "ARM:LE:32:Cortex") and
    optionally compiler_spec (e.g. "default"). Without language, Ghidra auto-detects
    the format (works for ELF, PE, Mach-O, etc.).

    Args:
        file_path: Absolute path to the binary file on disk
        project_folder: Destination folder in the Ghidra project (default: "/")
        language: Language ID for raw binaries (e.g. "ARM:LE:32:Cortex", "x86:LE:64:default")
        compiler_spec: Compiler spec ID (e.g. "default", "gcc"). Uses language default if omitted.
        auto_analyze: Start auto-analysis after import (default: true)
    """
    payload: dict = {
        "file_path": file_path,
        "project_folder": project_folder,
        "auto_analyze": auto_analyze,
    }
    if language:
        payload["language"] = language
    if compiler_spec:
        payload["compiler_spec"] = compiler_spec

    result = dispatch_post("/import_file", payload)

    # Parse result to check if analysis was started
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return result

    if data.get("data", {}).get("analyzing") and ctx is not None:
        program_name = data["data"].get("name", "unknown")
        # Capture the session before the tool call returns
        session = ctx.request_context.session

        async def _poll_analysis():
            """Poll analysis_status until analysis completes, then send log notification."""
            await asyncio.sleep(5)  # Initial delay
            for _ in range(360):  # Up to 30 minutes
                try:
                    status_text = dispatch_get(
                        "/analysis_status", {"program": program_name}
                    )
                    status = json.loads(status_text)
                    status_data = status.get("data", status)
                    if not status_data.get("analyzing", True):
                        fn_count = status_data.get("function_count", "?")
                        await session.send_log_message(
                            level="info",
                            data=f"Analysis complete for {program_name}: {fn_count} functions found",
                        )
                        return
                except Exception as e:
                    logger.debug(f"Analysis poll error for {program_name}: {e}")
                await asyncio.sleep(5)

        asyncio.create_task(_poll_analysis())

    return result


# ==========================================================================
# Auto-connect on startup
# ==========================================================================


def _auto_connect():
    """Try to auto-connect to a single running instance on startup."""
    global _active_socket, _active_tcp, _transport_mode, _connected_project

    # Try UDS first
    instances = discover_instances()
    if len(instances) == 1:
        _active_socket = instances[0]["socket"]
        _transport_mode = "uds"
        _connected_project = instances[0].get("project")
        logger.info(f"Auto-connecting via UDS to {_connected_project or 'unknown'}")
        try:
            count = _fetch_and_register_schema()
            logger.info(
                f"Auto-registered {count} tools from {_connected_project or 'unknown'}"
            )
            return
        except Exception as e:
            logger.warning(f"UDS auto-connect schema fetch failed: {e}")
            _active_socket = None
            _transport_mode = "none"
    elif len(instances) > 1:
        logger.info(
            f"Multiple UDS instances found ({len(instances)}). Use connect_instance() to choose."
        )

    # Try TCP fallback
    tcp_url = normalize_server_url(os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL))
    if not validate_server_url(tcp_url):
        logger.warning(f"Refusing to auto-connect to non-local URL: {tcp_url}")
        return
    try:
        _active_tcp = tcp_url
        _transport_mode = "tcp"
        count = _fetch_and_register_schema()
        logger.info(f"Auto-connected via TCP to {tcp_url}, registered {count} tools")
    except Exception:
        _active_tcp = None
        _transport_mode = "none"
        if not instances:
            logger.info(
                "No Ghidra instances found. Tools will be registered on connect_instance()."
            )


# ==========================================================================
# Main
# ==========================================================================


def main():
    global _lazy_mode, _default_groups, _tool_policy

    parser = argparse.ArgumentParser(
        description="GhidraMCP Bridge — MCP↔HTTP multiplexer"
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host for HTTP transport (streamable-http or sse)",
    )
    parser.add_argument(
        "--mcp-port", type=int, help="Port for HTTP transport (streamable-http or sse)"
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "streamable-http"],
        help="MCP transport: stdio (default, recommended for AI tools), "
        "streamable-http (recommended for web/HTTP clients), "
        "sse (deprecated, use streamable-http instead)",
    )
    parser.add_argument(
        "--lazy",
        action="store_true",
        default=True,
        help="Only load default tool groups on connect (default, recommended for OpenAI-first hosts)",
    )
    parser.add_argument(
        "--no-lazy",
        dest="lazy",
        action="store_false",
        help="Load all tool groups on connect",
    )
    parser.add_argument(
        "--default-groups",
        type=str,
        default=None,
        help="Comma-separated list of default tool groups to load on connect "
        "(default: listing,function,program)",
    )
    parser.add_argument(
        "--profile",
        action="append",
        choices=sorted(TOOL_PROFILES.keys()),
        help="Profile tag filter for visible tools (repeatable)",
    )
    parser.add_argument(
        "--category",
        action="append",
        help="Category filter for visible tools (repeatable)",
    )
    parser.add_argument(
        "--tag",
        action="append",
        help="Tag filter for visible tools (repeatable)",
    )
    parser.add_argument(
        "--read-only-only",
        action="store_true",
        help="Expose only tools marked as read-only",
    )
    parser.add_argument(
        "--allow-tools-file",
        type=str,
        help="Path to JSON array/object or newline-delimited allowlist of tool names",
    )
    parser.add_argument(
        "--approval-mode",
        type=str,
        default="never",
        choices=["never", "required", "all"],
        help="Visibility policy by approval class (default: never)",
    )
    parser.add_argument(
        "--export-allowlist",
        type=str,
        help="Write the filtered tool allowlist to a file (use '-' for stdout) and exit",
    )
    args = parser.parse_args()

    _lazy_mode = args.lazy
    if args.default_groups is not None:
        _default_groups = {
            g.strip() for g in args.default_groups.split(",") if g.strip()
        }
    elif args.category:
        _default_groups = _default_groups | {
            g.strip().lower() for g in args.category if g.strip()
        }

    allowlist: set[str] = set()
    if args.allow_tools_file:
        raw_allowlist = Path(args.allow_tools_file).read_text(encoding="utf-8").strip()
        if raw_allowlist:
            try:
                parsed_allowlist = json.loads(raw_allowlist)
            except json.JSONDecodeError:
                allowlist = {
                    line.strip() for line in raw_allowlist.splitlines() if line.strip()
                }
            else:
                if isinstance(parsed_allowlist, list):
                    allowlist = {
                        str(item).strip()
                        for item in parsed_allowlist
                        if str(item).strip()
                    }
                elif isinstance(parsed_allowlist, dict):
                    values = parsed_allowlist.get("allowed_tools", [])
                    allowlist = {
                        str(item).strip() for item in values if str(item).strip()
                    }

    _tool_policy = ToolPolicy(
        profiles={item.strip() for item in (args.profile or []) if item.strip()},
        categories={
            item.strip().lower() for item in (args.category or []) if item.strip()
        },
        tags={item.strip().lower() for item in (args.tag or []) if item.strip()},
        read_only_only=args.read_only_only,
        approval_mode=args.approval_mode,
        allowlist=allowlist,
    )
    _apply_static_tool_policy(_tool_policy)

    if not _lazy_mode:
        logger.info(
            "Loading all tool groups on startup (clients that don't support tools/list_changed need this)"
        )
    _auto_connect()

    if args.export_allowlist:
        allowed = export_allowed_tools(_tool_policy)
        payload = json.dumps({"allowed_tools": allowed}, indent=2)
        if args.export_allowlist == "-":
            print(payload)
        else:
            Path(args.export_allowlist).write_text(payload + "\n", encoding="utf-8")
        logger.info("Exported %d allowed tools", len(allowed))
        return

    mcp.settings.log_level = "INFO"
    mcp.settings.host = args.mcp_host
    if args.mcp_port:
        mcp.settings.port = args.mcp_port
    logger.info(f"Starting MCP bridge ({args.transport})")
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
