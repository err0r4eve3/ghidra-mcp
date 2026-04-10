"""
Endpoint Catalog Consistency Tests.

Verifies that:
1. Java services have @McpTool annotations that AnnotationScanner discovers
2. endpoints.json catalog stays in sync
3. Bridge dynamically registers from /mcp/schema (no hardcoded tools)
"""

import json
import os
import re
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
JAVA_SRC = PROJECT_ROOT / "src" / "main" / "java" / "com" / "xebyte"
CORE_SRC = JAVA_SRC / "core"
ENDPOINTS_JSON = PROJECT_ROOT / "tests" / "endpoints.json"


def count_mcptool_annotations() -> int:
    """Count @McpTool annotations across all service files."""
    count = 0
    for java_file in CORE_SRC.glob("*Service.java"):
        content = java_file.read_text(encoding="utf-8")
        count += len(re.findall(r"@McpTool\(", content))
    return count


def extract_annotated_paths() -> set[str]:
    """Extract all HTTP paths from @McpTool annotations."""
    paths = set()
    pattern = re.compile(r'@McpTool\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
    for java_file in CORE_SRC.glob("*Service.java"):
        content = java_file.read_text(encoding="utf-8")
        for match in pattern.finditer(content):
            paths.add(match.group(1))
    return paths


def extract_gui_only_paths() -> set[str]:
    """Extract GUI-only endpoint paths from GhidraMCPPlugin.java."""
    paths = set()
    plugin_file = JAVA_SRC / "GhidraMCPPlugin.java"
    if plugin_file.exists():
        content = plugin_file.read_text(encoding="utf-8")
        for match in re.finditer(r'server\.createContext\("([^"]+)"', content):
            paths.add(match.group(1))
    return paths


class TestAnnotatedEndpoints(unittest.TestCase):
    """Verify annotation-driven endpoint registration."""

    def test_has_annotated_endpoints(self):
        """Services should have @McpTool annotations."""
        count = count_mcptool_annotations()
        self.assertGreater(
            count, 100, f"Expected >100 annotated endpoints, found {count}"
        )

    def test_all_paths_start_with_slash(self):
        """All @McpTool paths should start with /."""
        for path in extract_annotated_paths():
            self.assertTrue(path.startswith("/"), f"Path should start with /: {path}")

    def test_no_duplicate_paths(self):
        """No two @McpTool annotations should have the same path."""
        paths = []
        pattern = re.compile(r'@McpTool\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
        for java_file in CORE_SRC.glob("*Service.java"):
            content = java_file.read_text(encoding="utf-8")
            for match in pattern.finditer(content):
                paths.append(match.group(1))
        duplicates = [p for p in paths if paths.count(p) > 1]
        # Some paths may appear twice (with/without program param overload)
        # but should not appear more than twice
        triplicates = [p for p in set(duplicates) if paths.count(p) > 2]
        self.assertEqual(len(triplicates), 0, f"Triplicate paths: {triplicates}")

    def test_services_exist(self):
        """Expected service files should exist."""
        expected_services = [
            "ListingService",
            "FunctionService",
            "CommentService",
            "SymbolLabelService",
            "XrefCallGraphService",
            "DataTypeService",
            "AnalysisService",
            "DocumentationHashService",
            "MalwareSecurityService",
            "ProgramScriptService",
        ]
        for svc in expected_services:
            path = CORE_SRC / f"{svc}.java"
            self.assertTrue(path.exists(), f"Missing service: {path}")


class TestEndpointsJson(unittest.TestCase):
    """Verify endpoints.json catalog validity."""

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_valid_json(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        self.assertIn("endpoints", data)

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_no_duplicate_paths(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        paths = [ep["path"] for ep in data.get("endpoints", [])]
        self.assertEqual(
            len(paths), len(set(paths)), "Duplicate paths in endpoints.json"
        )

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_endpoints_have_required_fields(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        for ep in data.get("endpoints", []):
            self.assertIn("path", ep, f"Missing 'path' in endpoint: {ep}")
            self.assertIn("method", ep, f"Missing 'method' in endpoint: {ep}")

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_schema_catalog_metadata_present(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        schema_catalog = data.get("schema_catalog", {})
        self.assertEqual(schema_catalog.get("schema_version"), "2.0")
        self.assertTrue(schema_catalog.get("capabilities", {}).get("catalog_metadata"))
        self.assertTrue(schema_catalog.get("capabilities", {}).get("tool_filtering"))
        self.assertTrue(
            schema_catalog.get("capabilities", {}).get("lazy_hydration_hints")
        )
        self.assertEqual(
            schema_catalog.get("default_approval", {}).get("GET"), "never"
        )
        self.assertEqual(
            schema_catalog.get("default_approval", {}).get("POST"), "required"
        )
        high_risk = set(schema_catalog.get("high_risk_categories", []))
        self.assertTrue({"project", "server", "script"} <= high_risk)


class TestBridgeIsDynamic(unittest.TestCase):
    """Verify the bridge uses dynamic registration, not hardcoded tools."""

    def test_bridge_has_few_static_tools(self):
        """Bridge should only have static tools (list_instances, connect_instance, tool group mgmt)."""
        bridge_path = PROJECT_ROOT / "bridge_mcp_ghidra.py"
        content = bridge_path.read_text(encoding="utf-8")
        tool_count = len(re.findall(r"@mcp\.tool\(\)", content))
        self.assertLessEqual(
            tool_count,
            10,
            f"Bridge has {tool_count} @mcp.tool() decorators. "
            "Expected <=10 (only static tools)",
        )

    def test_bridge_has_schema_registration(self):
        """Bridge should have register_tools_from_schema function."""
        bridge_path = PROJECT_ROOT / "bridge_mcp_ghidra.py"
        content = bridge_path.read_text(encoding="utf-8")
        self.assertIn("register_tools_from_schema", content)
        self.assertIn("/mcp/schema", content)

    def test_bridge_keeps_lazy_catalog_structure(self):
        """Bridge should stay metadata-driven instead of growing hardcoded tool logic."""
        bridge_path = PROJECT_ROOT / "bridge_mcp_ghidra.py"
        content = bridge_path.read_text(encoding="utf-8")
        for needle in [
            "class ToolCatalog",
            "class ToolPolicy",
            "class HydrationCache",
            "CORE_GROUPS",
            "def register_tools_from_schema",
            "def _load_group",
            "def _fetch_and_register_schema",
        ]:
            self.assertIn(
                needle,
                content,
                f"Bridge is missing lazy catalog component: {needle}",
            )


class TestAnnotationScannerExists(unittest.TestCase):
    """Verify AnnotationScanner infrastructure."""

    def test_annotation_scanner_exists(self):
        path = CORE_SRC / "AnnotationScanner.java"
        self.assertTrue(path.exists())

    def test_mcptool_annotation_exists(self):
        path = CORE_SRC / "McpTool.java"
        self.assertTrue(path.exists())

    def test_param_annotation_exists(self):
        path = CORE_SRC / "Param.java"
        self.assertTrue(path.exists())

    def test_mcp_tool_group_annotation_exists(self):
        path = CORE_SRC / "McpToolGroup.java"
        self.assertTrue(path.exists())

    def test_scanner_has_schema_method(self):
        content = (CORE_SRC / "AnnotationScanner.java").read_text(encoding="utf-8")
        self.assertIn("generateSchema", content)
        self.assertIn("ToolDescriptor", content)

    def test_gui_http_server_uses_bounded_worker_pool(self):
        content = (JAVA_SRC / "GhidraMCPPlugin.java").read_text(encoding="utf-8")
        self.assertIn("newFixedThreadPool", content)
        self.assertIn("GhidraMCP-HTTP-Worker", content)
        self.assertNotIn("server.setExecutor(null)", content)

    def test_gui_http_server_closes_short_lived_connections(self):
        content = (JAVA_SRC / "GhidraMCPPlugin.java").read_text(encoding="utf-8")
        self.assertIn('headers.set("Connection", "close")', content)
        self.assertIn("exchange.close()", content)
        self.assertNotIn('headers.set("Connection", "keep-alive")', content)

    def test_scanner_has_catalog_metadata_fields(self):
        content = (CORE_SRC / "AnnotationScanner.java").read_text(encoding="utf-8")
        for needle in [
            "schema_version",
            "catalog_metadata",
            "tool_filtering",
            "lazy_hydration_hints",
            "read_only_hint",
            "approval_default",
            "profile_tags",
            "openai_summary",
            "surface",
        ]:
            self.assertIn(needle, content, f"Missing schema metadata field: {needle}")

    def test_mcp_tool_annotation_has_openai_catalog_accessors(self):
        content = (CORE_SRC / "McpTool.java").read_text(encoding="utf-8")
        for needle in [
            "String title()",
            "String[] tags()",
            "String sideEffect()",
            "String readOnlyHint()",
            "String approvalDefault()",
            "String visibility()",
            "String[] profileTags()",
            "String openaiSummary()",
        ]:
            self.assertIn(needle, content, f"Missing @McpTool accessor: {needle}")

    def test_all_services_have_tool_group(self):
        """All service files should have @McpToolGroup annotation."""
        expected = [
            "ListingService",
            "FunctionService",
            "CommentService",
            "SymbolLabelService",
            "XrefCallGraphService",
            "DataTypeService",
            "AnalysisService",
            "DocumentationHashService",
            "MalwareSecurityService",
            "ProgramScriptService",
        ]
        for name in expected:
            path = CORE_SRC / f"{name}.java"
            if path.exists():
                content = path.read_text(encoding="utf-8")
                self.assertIn(
                    "@McpToolGroup",
                    content,
                    f"{name}.java missing @McpToolGroup annotation",
                )


if __name__ == "__main__":
    unittest.main()
