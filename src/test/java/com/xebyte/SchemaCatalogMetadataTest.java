package com.xebyte;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.McpTool;
import com.xebyte.core.McpToolGroup;
import com.xebyte.core.Param;
import com.xebyte.core.Response;
import junit.framework.TestCase;

import java.util.List;

/**
 * Contract tests for OpenAI-first schema metadata emitted by AnnotationScanner.
 */
public class SchemaCatalogMetadataTest extends TestCase {

    @McpToolGroup(value = "analysis", description = "Analysis tools")
    private static class DummyCatalogService {

        @McpTool(path = "/catalog_read", description = "List candidate functions")
        public Response readEndpoint(@Param("program") String program) {
            return Response.text("ok");
        }

        @McpTool(path = "/catalog_write", method = "POST", category = "rename",
            description = "Rename a function symbol")
        public Response writeEndpoint(@Param("name") String name) {
            return Response.text("ok");
        }

        @McpTool(path = "/catalog_debugger", category = "debugger",
            description = "Report debugger status")
        public Response debuggerEndpoint() {
            return Response.text("ok");
        }
    }

    public void testMcpToolAnnotationExposesCatalogMetadataFields() throws Exception {
        Class<McpTool> annotationClass = McpTool.class;
        assertNotNull(annotationClass.getDeclaredMethod("title"));
        assertNotNull(annotationClass.getDeclaredMethod("tags"));
        assertNotNull(annotationClass.getDeclaredMethod("sideEffect"));
        assertNotNull(annotationClass.getDeclaredMethod("readOnlyHint"));
        assertNotNull(annotationClass.getDeclaredMethod("approvalDefault"));
        assertNotNull(annotationClass.getDeclaredMethod("visibility"));
        assertNotNull(annotationClass.getDeclaredMethod("profileTags"));
        assertNotNull(annotationClass.getDeclaredMethod("openaiSummary"));
    }

    public void testGenerateSchemaIncludesTopLevelCatalogMetadata() {
        AnnotationScanner scanner = new AnnotationScanner(new DummyCatalogService());

        String schemaJson = scanner.generateSchema();

        assertTrue(schemaJson.contains("\"schema_version\""));
        assertTrue(schemaJson.contains("\"capabilities\""));
        assertTrue(schemaJson.contains("\"catalog_metadata\""));
        assertTrue(schemaJson.contains("\"tool_filtering\""));
        assertTrue(schemaJson.contains("\"lazy_hydration_hints\""));
    }

    public void testReadEndpointsDefaultToReadOnlyNeverApproval() {
        AnnotationScanner scanner = new AnnotationScanner(new DummyCatalogService());
        AnnotationScanner.ToolDescriptor descriptor = descriptorFor(scanner, "/catalog_read");

        assertEquals("read", descriptor.sideEffect());
        assertTrue(descriptor.readOnlyHint());
        assertEquals("never", descriptor.approvalDefault());
        assertEquals("tool", descriptor.surface());
    }

    public void testPostEndpointsDefaultToWriteAndRequireApproval() {
        AnnotationScanner scanner = new AnnotationScanner(new DummyCatalogService());
        AnnotationScanner.ToolDescriptor descriptor = descriptorFor(scanner, "/catalog_write");

        assertEquals("write", descriptor.sideEffect());
        assertFalse(descriptor.readOnlyHint());
        assertEquals("required", descriptor.approvalDefault());
    }

    public void testDebuggerCategoryRequiresApprovalEvenForGet() {
        AnnotationScanner scanner = new AnnotationScanner(new DummyCatalogService());
        AnnotationScanner.ToolDescriptor descriptor = descriptorFor(scanner, "/catalog_debugger");

        assertEquals("required", descriptor.approvalDefault());
    }

    private static AnnotationScanner.ToolDescriptor descriptorFor(
        AnnotationScanner scanner,
        String path
    ) {
        List<AnnotationScanner.ToolDescriptor> descriptors = scanner.getDescriptors();
        return descriptors.stream()
            .filter(descriptor -> path.equals(descriptor.path()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("Missing descriptor for " + path));
    }
}
