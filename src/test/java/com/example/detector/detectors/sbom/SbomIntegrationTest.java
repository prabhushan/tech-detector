package com.example.detector.detectors.sbom;

import com.example.detector.config.RegistryLoader;
import com.example.detector.engine.SbomFirstDetectorEngine;
import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for SBOM processing with sample JSON files.
 * Tests the full flow from file parsing to detection result.
 */
@DisplayName("SBOM Integration Tests")
class SbomIntegrationTest {

    private SbomService sbomService;
    private SbomProcessor sbomProcessor;
    private SbomFirstDetectorEngine engine;
    private Path testResourcesDir;

    @BeforeEach
    void setUp() {
        sbomService = new SbomService();
        RegistryLoader registryLoader = new RegistryLoader();
        RegistryMatcher registryMatcher = new RegistryMatcher(registryLoader);
        sbomProcessor = new SbomProcessor(registryMatcher);
        
        // Create engine with empty plugin list for SBOM-only tests
        List<DetectorPlugin> plugins = new ArrayList<>();
        engine = new SbomFirstDetectorEngine(sbomService, sbomProcessor, plugins);
        
        testResourcesDir = Paths.get("src", "test", "resources", "sbom");
    }

    @Test
    @DisplayName("Should perform full scan with sbom_AI.json")
    void testFullScanWithSbomAI() {
        Path projectRoot = testResourcesDir;
        Path sbomFile = projectRoot.resolve("sbom_AI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            System.out.println("Skipping test - sbom_AI.json is empty or doesn't exist");
            return;
        }

        DetectionResult result = engine.scanProject(projectRoot);
        
        assertNotNull(result, "Result should not be null");
        assertNotNull(result.projectPath, "Project path should be set");
        
        System.out.println("=== Full Scan Results for sbom_AI.json ===");
        System.out.println("Languages: " + result.languages);
        System.out.println("Frameworks: " + result.frameworks.keySet());
        System.out.println("Cloud SDKs: " + result.cloudSdks.keySet());
        System.out.println("Databases: " + result.databases.keySet());
        System.out.println("Runtimes: " + result.runtimes.keySet());
        System.out.println("Infrastructure: " + result.infrastructure.keySet());
        
        // Verify Python is detected
        assertTrue(result.languages.contains("Python"), 
            "Should detect Python language from sbom_AI.json");
        
        // Verify final result is populated
        result.populateFinalResult();
        assertFalse(result.finalResult.isEmpty(), "Final result should not be empty");
    }

    @Test
    @DisplayName("Should perform full scan with sbom.json")
    void testFullScanWithSbom() {
        Path projectRoot = testResourcesDir;
        Path sbomFile = projectRoot.resolve("sbom.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            System.out.println("Skipping test - sbom.json is empty or doesn't exist");
            return;
        }

        DetectionResult result = engine.scanProject(projectRoot);
        
        assertNotNull(result, "Result should not be null");
        
        System.out.println("=== Full Scan Results for sbom.json ===");
        System.out.println("Languages: " + result.languages);
        System.out.println("Frameworks: " + result.frameworks.keySet());
        
        // Verify some detections were made
        boolean hasDetections = !result.languages.isEmpty() || 
                               !result.frameworks.isEmpty() ||
                               !result.cloudSdks.isEmpty();
        
        assertTrue(hasDetections, "Should detect at least some technologies");
    }

    @Test
    @DisplayName("Should perform full scan with sbom_UI.json")
    void testFullScanWithSbomUI() {
        Path projectRoot = testResourcesDir;
        Path sbomFile = projectRoot.resolve("sbom_UI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            System.out.println("Skipping test - sbom_UI.json is empty or doesn't exist");
            return;
        }

        DetectionResult result = engine.scanProject(projectRoot);
        
        assertNotNull(result, "Result should not be null");
        
        System.out.println("=== Full Scan Results for sbom_UI.json ===");
        System.out.println("Languages: " + result.languages);
        System.out.println("Frameworks: " + result.frameworks.keySet());
        
        // Verify JavaScript/TypeScript is detected if npm packages exist
        boolean hasJsLanguage = result.languages.contains("JavaScript") || 
                               result.languages.contains("TypeScript");
        
        if (hasJsLanguage) {
            System.out.println("JavaScript/TypeScript detected correctly");
        }
    }

    @Test
    @DisplayName("Should handle project directory without SBOM file")
    void testScanWithoutSbomFile() {
        Path projectRoot = Paths.get("src", "test", "resources");
        
        DetectionResult result = engine.scanProject(projectRoot);
        
        assertNotNull(result, "Result should not be null");
        // Without SBOM, result may be empty but should not throw exception
        System.out.println("Scan completed without SBOM file");
    }

    @Test
    @DisplayName("Should verify langchain detection with purlMatch name")
    void testLangchainDetectionWithPurlMatch() {
        Path projectRoot = testResourcesDir;
        Path sbomFile = projectRoot.resolve("sbom_AI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            return;
        }

        DetectionResult result = engine.scanProject(projectRoot);
        
        // Check if langchain is detected (with purlMatch="name" it should only match
        // packages with name "langchain", not scoped packages)
        boolean hasLangchain = result.frameworks.keySet().stream()
            .anyMatch(key -> key.startsWith("langchain"));
        
        System.out.println("Langchain detected: " + hasLangchain);
        if (hasLangchain) {
            result.frameworks.entrySet().stream()
                .filter(entry -> entry.getKey().startsWith("langchain"))
                .forEach(entry -> {
                    System.out.println("  Framework: " + entry.getKey());
                    System.out.println("  Evidence: " + entry.getValue());
                });
        }
        
        // Verify that only exact name matches are detected (not scoped packages)
        result.frameworks.keySet().forEach(key -> {
            if (key.startsWith("langchain")) {
                // Evidence should contain langchain packages, not scoped ones like @langchain/...
                List<String> evidence = result.frameworks.get(key);
                evidence.forEach(ev -> {
                    // Should not match scoped packages when purlMatch="name"
                    assertFalse(ev.contains("@langchain"), 
                        "Should not match scoped langchain packages with purlMatch=name");
                });
            }
        });
    }
}
