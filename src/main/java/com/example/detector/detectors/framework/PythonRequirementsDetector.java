package com.example.detector.detectors.framework;

import com.example.detector.config.RegistryLoader;
import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.List;

@Component
public class PythonRequirementsDetector implements DetectorPlugin {

    private final RegistryLoader registryLoader;

    public PythonRequirementsDetector(RegistryLoader registryLoader) {
        this.registryLoader = registryLoader;
    }

    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();

        // Only process requirements.txt, Pipfile, or pyproject.toml
        if (!name.equals("requirements.txt") && !name.equals("pipfile") && !name.equals("pyproject.toml")) {
            return;
        }

        try {
            String content = Files.readString(file, StandardCharsets.UTF_8);
            JsonNode registry = registryLoader.getRegistry();

            // Detect frameworks
            detectFromRegistry(registry, "frameworks", content, file, result::addFramework);

            // Detect cloud SDKs
            detectFromRegistry(registry, "cloud_sdks", content, file, result::addCloudSdk);

            // Detect databases
            detectFromRegistry(registry, "databases", content, file, result::addDatabase);

            // Detect AI/ML libraries
            if (registry.has("ai_ml")) {
                detectFromRegistry(registry, "ai_ml", content, file, result::addFramework);
            }

            // Detect vector databases
            if (registry.has("vector_databases")) {
                detectFromRegistry(registry, "vector_databases", content, file, result::addDatabase);
            }

            // Detect testing frameworks
            if (registry.has("testing")) {
                detectFromRegistry(registry, "testing", content, file, result::addFramework);
            }

            // Detect ORMs
            if (registry.has("orm")) {
                detectFromRegistry(registry, "orm", content, file, result::addFramework);
            }

            // Detect message queues
            if (registry.has("message_queue")) {
                detectFromRegistry(registry, "message_queue", content, file, result::addInfrastructure);
            }

        } catch (Exception ex) {
            // ignore
        }
    }

    private void detectFromRegistry(JsonNode registry, String category, String content, Path file, ResultAdder adder) {
        if (!registry.has(category)) return;

        JsonNode categoryNode = registry.get(category);
        Iterator<String> fieldNames = categoryNode.fieldNames();

        while (fieldNames.hasNext()) {
            String tech = fieldNames.next();
            JsonNode techNode = categoryNode.get(tech);

            if (techNode.has("indicators")) {
                JsonNode indicators = techNode.get("indicators");
                for (JsonNode indicator : indicators) {
                    String indicatorStr = indicator.asText().toLowerCase();
                    String version = extractVersion(content, indicatorStr);
                    if (version != null) {
                        adder.add(formatTechName(tech), version);
                        break; // Only add once per technology
                    }
                }
            }
        }
    }

    private String extractVersion(String content, String packageName) {
        // Split content into lines
        String[] lines = content.split("\\r?\\n");

        for (String line : lines) {
            String trimmed = line.trim();
            String lowerLine = trimmed.toLowerCase();

            // Skip comments
            if (lowerLine.startsWith("#")) continue;

            // Check if line contains the package
            if (lowerLine.startsWith(packageName)) {
                // Extract version using regex
                // Matches: package==1.0.0, package>=1.0.0, package~=1.0.0, etc.
                if (trimmed.matches("(?i)" + packageName + "[>=<~!]*.*")) {
                    return trimmed; // Return the full line with version
                }
            }
        }
        return null;
    }

    private String formatTechName(String tech) {
        // Convert hyphenated names to proper case
        if (tech.contains("-")) {
            String[] parts = tech.split("-");
            StringBuilder formatted = new StringBuilder();
            for (String part : parts) {
                if (formatted.length() > 0) formatted.append(" ");
                formatted.append(Character.toUpperCase(part.charAt(0)));
                if (part.length() > 1) {
                    formatted.append(part.substring(1));
                }
            }
            return formatted.toString();
        }
        // Simple capitalization
        return Character.toUpperCase(tech.charAt(0)) + tech.substring(1);
    }

    @FunctionalInterface
    private interface ResultAdder {
        void add(String name, String evidence);
    }
}
