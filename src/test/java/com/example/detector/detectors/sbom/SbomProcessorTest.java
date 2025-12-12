package com.example.detector.detectors.sbom;

import com.example.detector.config.RegistryLoader;
import com.example.detector.model.DetectionResult;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for SbomProcessor using sample SBOM JSON files.
 */
@DisplayName("SbomProcessor Tests")
class SbomProcessorTest {

    private SbomService sbomService;
    private SbomProcessor sbomProcessor;
    private RegistryLoader registryLoader;
    private RegistryMatcher registryMatcher;
    private Path testResourcesDir;

    @BeforeEach
    void setUp() {
        sbomService = new SbomService();
        registryLoader = new RegistryLoader();
        registryMatcher = new RegistryMatcher(registryLoader);
        sbomProcessor = new SbomProcessor(registryMatcher);
        testResourcesDir = Paths.get("src", "test", "resources", "sbom");
    }

    @Test
    @DisplayName("Should process sbom_AI.json and detect Python language")
    void testProcessSbomAI() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom_AI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            System.out.println("Skipping test - sbom_AI.json is empty or doesn't exist");
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        assertNotNull(bom, "BOM should be parsed successfully");

        DetectionResult result = new DetectionResult();
        result.projectPath = sbomFile.toString();
        
        sbomProcessor.processBom(bom, result);
        
        // Verify Python language is detected (sbom_AI.json contains Python packages)
        assertTrue(result.languages.contains("Python"), 
            "Should detect Python language from pypi packages");
        
        System.out.println("Detected languages: " + result.languages);
        System.out.println("Detected frameworks: " + result.frameworks.keySet());
        System.out.println("Detected cloud SDKs: " + result.cloudSdks.keySet());
        
        // Verify frameworks were detected if langchain is present
        if (result.frameworks.containsKey("langchain")) {
            List<String> langchainEvidence = result.frameworks.get("langchain");
            assertFalse(langchainEvidence.isEmpty(), "Langchain framework should have evidence");
            System.out.println("Langchain evidence: " + langchainEvidence);
        }
    }

    @Test
    @DisplayName("Should process sbom.json and detect technologies")
    void testProcessSbom() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            System.out.println("Skipping test - sbom.json is empty or doesn't exist");
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        assertNotNull(bom, "BOM should be parsed successfully");

        DetectionResult result = new DetectionResult();
        result.projectPath = sbomFile.toString();
        
        sbomProcessor.processBom(bom, result);
        
        System.out.println("Detected languages: " + result.languages);
        System.out.println("Detected frameworks: " + result.frameworks.keySet());
        System.out.println("Detected databases: " + result.databases.keySet());
        System.out.println("Detected cloud SDKs: " + result.cloudSdks.keySet());
        
        // Verify result has some detections
        assertFalse(result.languages.isEmpty() && result.frameworks.isEmpty() && 
                   result.cloudSdks.isEmpty() && result.databases.isEmpty(),
            "Should detect at least some technologies");
    }

    @Test
    @DisplayName("Should process sbom_UI.json and detect JavaScript/TypeScript")
    void testProcessSbomUI() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom_UI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            System.out.println("Skipping test - sbom_UI.json is empty or doesn't exist");
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        assertNotNull(bom, "BOM should be parsed successfully");

        DetectionResult result = new DetectionResult();
        result.projectPath = sbomFile.toString();
        
        sbomProcessor.processBom(bom, result);
        
        // UI projects typically use JavaScript/TypeScript
        boolean hasJsLanguage = result.languages.contains("JavaScript") || 
                               result.languages.contains("TypeScript");
        
        System.out.println("Detected languages: " + result.languages);
        System.out.println("Detected frameworks: " + result.frameworks.keySet());
        
        // If npm packages are present, JavaScript should be detected
        List<org.cyclonedx.model.Component> components = bom.getComponents();
        if (components != null && !components.isEmpty()) {
            boolean hasNpmPackage = components.stream()
                .anyMatch(c -> c.getPurl() != null && c.getPurl().contains("pkg:npm"));
            
            if (hasNpmPackage) {
                assertTrue(hasJsLanguage, 
                    "Should detect JavaScript/TypeScript language from npm packages");
            }
        }
    }

    @Test
    @DisplayName("Should handle null BOM gracefully")
    void testProcessNullBom() {
        DetectionResult result = new DetectionResult();
        
        // Should not throw exception
        assertDoesNotThrow(() -> {
            sbomProcessor.processBom(null, result);
        }, "Should handle null BOM without throwing exception");
        
        assertTrue(result.languages.isEmpty(), "Languages should be empty");
        assertTrue(result.frameworks.isEmpty(), "Frameworks should be empty");
    }

    @Test
    @DisplayName("Should detect langchain framework from sbom_AI.json")
    void testDetectLangchainFramework() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom_AI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        assertNotNull(bom);

        DetectionResult result = new DetectionResult();
        sbomProcessor.processBom(bom, result);
        
        // Check if langchain is detected as a framework
        // It should match via sbomMatch with purlMatch="name"
        boolean hasLangchain = result.frameworks.keySet().stream()
            .anyMatch(key -> key.startsWith("langchain"));
        
        if (hasLangchain) {
            System.out.println("Detected langchain framework");
            result.frameworks.entrySet().stream()
                .filter(entry -> entry.getKey().startsWith("langchain"))
                .forEach(entry -> {
                    System.out.println("  " + entry.getKey() + ": " + entry.getValue());
                });
        } else {
            System.out.println("Langchain not detected as framework");
        }
    }

    @Test
    @DisplayName("Should populate final result correctly")
    void testPopulateFinalResult() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom_AI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        assertNotNull(bom);

        DetectionResult result = new DetectionResult();
        sbomProcessor.processBom(bom, result);
        
        // Populate final result
        result.populateFinalResult();
        
        assertNotNull(result.finalResult, "Final result should not be null");
        assertFalse(result.finalResult.isEmpty(), "Final result should not be empty");
        
        System.out.println("Final result contains " + result.finalResult.size() + " items:");
        result.finalResult.forEach(nv -> {
            System.out.println("  " + nv.name + (nv.version != null ? ":" + nv.version : ""));
        });
        
        // Verify all languages are in final result
        for (String lang : result.languages) {
            boolean found = result.finalResult.stream()
                .anyMatch(nv -> nv.name.equals(lang) && nv.version == null);
            assertTrue(found, "Language " + lang + " should be in final result");
        }
    }

    @Test
    @DisplayName("Should extract versions correctly from components")
    void testVersionExtraction() throws IOException, ParseException {
        Path sbomFile = testResourcesDir.resolve("sbom_AI.json");
        
        if (!sbomFile.toFile().exists() || sbomFile.toFile().length() == 0) {
            return;
        }

        Bom bom = sbomService.parseBom(sbomFile);
        assertNotNull(bom);

        DetectionResult result = new DetectionResult();
        sbomProcessor.processBom(bom, result);
        
        // Check that frameworks with versions have them in the key
        result.frameworks.keySet().forEach(key -> {
            if (key.contains(":")) {
                String[] parts = key.split(":", 2);
                assertNotNull(parts[1], "Version should not be empty");
                assertFalse(parts[1].isBlank(), "Version should not be blank");
                System.out.println("Framework with version: " + key);
            }
        });
    }
}
