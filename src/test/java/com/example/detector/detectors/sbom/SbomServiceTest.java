package com.example.detector.detectors.sbom;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for SbomService using sample SBOM JSON files.
 */
@DisplayName("SbomService Tests")
class SbomServiceTest {

    private SbomService sbomService;
    private Path testResourcesDir;

    @BeforeEach
    void setUp() {
        sbomService = new SbomService();
        testResourcesDir = Paths.get("src", "test", "resources", "sbom");
    }

    @Test
    @DisplayName("Should parse sbom.json successfully")
    void testParseSbomJson() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom.json");
        
        // Skip test if file is empty or doesn't exist
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            System.out.println("Skipping test - sbom.json is empty or doesn't exist");
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        
        assertNotNull(bom, "BOM should be parsed successfully");
        assertNotNull(bom.getComponents(), "BOM should have components");
        
        List<Component> components = bom.getComponents();
        assertFalse(components.isEmpty(), "BOM should contain at least one component");
        
        // Log first few components for debugging
        System.out.println("Parsed " + components.size() + " components from sbom.json");
        if (!components.isEmpty()) {
            Component first = components.get(0);
            System.out.println("First component: " + first.getName() + " @ " + first.getVersion());
        }
    }

    @Test
    @DisplayName("Should parse sbom_AI.json successfully")
    void testParseSbomAIJson() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom_AI.json");
        
        assertTrue(sbomFile.toFile().exists(), "sbom_AI.json should exist");
        assertTrue(sbomFile.toFile().length() > 0, "sbom_AI.json should not be empty");

        Bom bom = sbomService.parseBom(sbomFile);
        
        assertNotNull(bom, "BOM should be parsed successfully");
        assertNotNull(bom.getComponents(), "BOM should have components");
        
        List<Component> components = bom.getComponents();
        assertFalse(components.isEmpty(), "BOM should contain at least one component");
        
        // Verify metadata
        assertNotNull(bom.getMetadata(), "BOM should have metadata");
        assertEquals("CycloneDX", bom.getBomFormat(), "BOM format should be CycloneDX");
        
        // Check for Python components (sbom_AI.json should contain Python packages)
        boolean hasPythonComponent = components.stream()
            .anyMatch(c -> c.getPurl() != null && c.getPurl().contains("pkg:pypi"));
        assertTrue(hasPythonComponent, "BOM should contain Python components");
        
        // Log details
        System.out.println("Parsed " + components.size() + " components from sbom_AI.json");
        System.out.println("BOM spec version: " + bom.getSpecVersion());
        System.out.println("BOM version: " + bom.getVersion());
        
        // Verify langchain is present (from sample data)
        boolean hasLangchain = components.stream()
            .anyMatch(c -> "langchain".equals(c.getName()));
        if (hasLangchain) {
            Component langchain = components.stream()
                .filter(c -> "langchain".equals(c.getName()))
                .findFirst()
                .orElse(null);
            assertNotNull(langchain);
            assertNotNull(langchain.getPurl());
            assertTrue(langchain.getPurl().contains("pkg:pypi"));
            System.out.println("Found langchain: " + langchain.getVersion());
        }
    }

    @Test
    @DisplayName("Should parse sbom_UI.json successfully")
    void testParseSbomUIJson() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom_UI.json");
        
        // Skip test if file is empty
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            System.out.println("Skipping test - sbom_UI.json is empty or doesn't exist");
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        
        assertNotNull(bom, "BOM should be parsed successfully");
        assertNotNull(bom.getComponents(), "BOM should have components");
        
        List<Component> components = bom.getComponents();
        System.out.println("Parsed " + components.size() + " components from sbom_UI.json");
        
        // Check for npm/node components (UI projects typically use npm)
        if (!components.isEmpty()) {
            boolean hasNpmComponent = components.stream()
                .anyMatch(c -> c.getPurl() != null && c.getPurl().contains("pkg:npm"));
            System.out.println("Contains npm components: " + hasNpmComponent);
        }
    }

    @Test
    @DisplayName("Should handle non-existent file gracefully")
    void testParseNonExistentFile() {
        Path nonExistentFile = testResourcesDir.resolve("non-existent.json");
        
        assertThrows(IOException.class, () -> {
            sbomService.parseBom(nonExistentFile);
        }, "Should throw IOException for non-existent file");
    }

    @Test
    @DisplayName("Should handle invalid JSON file gracefully")
    void testParseInvalidJson() throws IOException {
        // Create a temporary invalid JSON file
        Path invalidFile = testResourcesDir.resolve("invalid.json");
        try {
            java.nio.file.Files.write(invalidFile, "{ invalid json }".getBytes());
            
            assertThrows(ParseException.class, () -> {
                sbomService.parseBom(invalidFile);
            }, "Should throw ParseException for invalid JSON");
        } finally {
            // Clean up
            if (invalidFile.toFile().exists()) {
                invalidFile.toFile().delete();
            }
        }
    }

    @Test
    @DisplayName("Should extract component metadata correctly from sbom_AI.json")
    void testComponentMetadata() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom_AI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        assertNotNull(bom);
        
        List<Component> components = bom.getComponents();
        assertFalse(components.isEmpty());
        
        // Verify components have required fields
        for (Component component : components) {
            assertNotNull(component.getName(), "Component should have a name");
            assertNotNull(component.getType(), "Component should have a type");
            
            // PURL is optional but if present should be valid format
            if (component.getPurl() != null) {
                assertTrue(component.getPurl().startsWith("pkg:"), 
                    "PURL should start with 'pkg:'");
            }
        }
    }
}
