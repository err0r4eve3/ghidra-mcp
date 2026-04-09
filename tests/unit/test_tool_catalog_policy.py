"""
Tests for OpenAI-first tool catalog metadata, policy filtering, and schema caching.
"""

import inspect
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


RAW_SCHEMA = {
    "schema_version": "2.0",
    "capabilities": {
        "catalog_metadata": True,
        "tool_filtering": True,
        "lazy_hydration_hints": True,
    },
    "tools": [
        {
            "path": "/list_functions",
            "method": "GET",
            "description": "List functions",
            "category": "listing",
            "category_description": "List program data",
            "params": [],
            "tags": ["listing", "reverse-engineering"],
            "title": "List Functions",
            "side_effect": "read",
            "read_only_hint": True,
            "approval_default": "never",
            "visibility": "model",
            "profile_tags": ["re"],
            "openai_summary": "Use this when you need a function listing.",
            "surface": "tool",
        },
        {
            "path": "/rename_function",
            "method": "POST",
            "description": "Rename function",
            "category": "rename",
            "category_description": "Rename symbols",
            "params": [
                {"name": "old_name", "type": "string", "required": True},
                {"name": "new_name", "type": "string", "required": True},
            ],
            "tags": ["rename"],
            "title": "Rename Function",
            "side_effect": "write",
            "read_only_hint": False,
            "approval_default": "required",
            "visibility": "model",
            "profile_tags": ["re"],
            "openai_summary": "Use this when you need to rename a function.",
            "surface": "tool",
        },
        {
            "path": "/debugger_status",
            "method": "GET",
            "description": "Debugger status",
            "category": "debugger",
            "category_description": "Debugger endpoints",
            "params": [],
            "tags": ["debugger"],
            "title": "Debugger Status",
            "side_effect": "read",
            "read_only_hint": True,
            "approval_default": "required",
            "visibility": "model",
            "profile_tags": [],
            "openai_summary": "Use this when you need debugger state.",
            "surface": "tool",
        },
    ],
    "count": 3,
}


class TestToolCatalogDefaults:
    def test_catalog_entries_preserve_schema_metadata(self):
        from bridge_mcp_ghidra import ToolCatalog, get_static_tool_catalog

        catalog = ToolCatalog.from_schema(RAW_SCHEMA, get_static_tool_catalog())
        entry = catalog.entries["list_functions"]

        assert entry.side_effect == "read"
        assert entry.read_only_hint is True
        assert entry.approval_default == "never"
        assert entry.surface == "tool"
        assert "reverse-engineering" in entry.tags

    def test_static_catalog_entries_have_policy_metadata(self):
        from bridge_mcp_ghidra import get_static_tool_catalog

        static_catalog = get_static_tool_catalog()

        assert static_catalog["list_instances"].read_only_hint is True
        assert static_catalog["import_file"].approval_default == "required"


class TestToolPolicyFiltering:
    def test_default_policy_excludes_required_approval_tools(self):
        from bridge_mcp_ghidra import ToolCatalog, ToolPolicy, get_static_tool_catalog

        catalog = ToolCatalog.from_schema(RAW_SCHEMA, get_static_tool_catalog())
        names = catalog.filter(ToolPolicy(), include_static=False)

        assert "list_functions" in names
        assert "rename_function" not in names
        assert "debugger_status" not in names

    def test_profile_and_category_filters_stack(self):
        from bridge_mcp_ghidra import ToolCatalog, ToolPolicy, get_static_tool_catalog

        catalog = ToolCatalog.from_schema(RAW_SCHEMA, get_static_tool_catalog())
        names = catalog.filter(
            ToolPolicy(
                profiles={"re"},
                categories={"listing"},
                read_only_only=True,
                approval_mode="never",
            ),
            include_static=False,
        )

        assert names == ["list_functions"]

    def test_allowlist_is_final_visible_set(self):
        from bridge_mcp_ghidra import ToolCatalog, ToolPolicy, get_static_tool_catalog

        catalog = ToolCatalog.from_schema(RAW_SCHEMA, get_static_tool_catalog())
        names = catalog.filter(
            ToolPolicy(allowlist={"rename_function"}, approval_mode="all"),
            include_static=False,
        )

        assert names == ["rename_function"]


class TestHydrationCache:
    @patch("bridge_mcp_ghidra.do_request")
    def test_directory_fetch_is_cached_until_refresh(self, mock_request):
        from bridge_mcp_ghidra import HydrationCache

        mock_request.return_value = (json.dumps(RAW_SCHEMA), 200)

        cache = HydrationCache()
        first = cache.get_catalog()
        second = cache.get_catalog()
        refreshed = cache.get_catalog(force_refresh=True)

        assert first is second
        assert refreshed is not None
        assert mock_request.call_count == 2


class TestRegisterSchemaToolsWithPolicy:
    @patch("bridge_mcp_ghidra.mcp")
    def test_registers_only_policy_selected_dynamic_tools(self, mock_mcp):
        import bridge_mcp_ghidra as bridge

        mock_tool_decorator = MagicMock(return_value=lambda f: f)
        mock_mcp.tool.return_value = mock_tool_decorator

        schema = bridge._parse_schema(RAW_SCHEMA)
        count = bridge.register_tools_from_schema(schema, policy=bridge.ToolPolicy())

        assert count == 1
        registered_names = [
            call.kwargs.get("name", call.args[0] if call.args else None)
            for call in mock_mcp.tool.call_args_list
        ]
        assert registered_names == ["list_functions"]

    @patch("bridge_mcp_ghidra.do_request")
    def test_export_allowed_tools_uses_filtered_catalog(self, mock_request):
        import bridge_mcp_ghidra as bridge

        mock_request.return_value = (json.dumps(RAW_SCHEMA), 200)
        bridge._hydration_cache = bridge.HydrationCache()

        names = bridge.export_allowed_tools(
            bridge.ToolPolicy(
                allowlist={"rename_function"},
                approval_mode="all",
            )
        )

        assert names == ["rename_function"]


class TestSchemaParserMetadata:
    def test_parse_schema_keeps_catalog_metadata(self):
        import bridge_mcp_ghidra as bridge

        parsed = bridge._parse_schema(RAW_SCHEMA)
        tool_def = next(td for td in parsed if td["name"] == "list_functions")

        assert tool_def["title"] == "List Functions"
        assert tool_def["read_only_hint"] is True
        assert tool_def["approval_default"] == "never"
        assert tool_def["profile_tags"] == ["re"]
        assert tool_def["surface"] == "tool"
