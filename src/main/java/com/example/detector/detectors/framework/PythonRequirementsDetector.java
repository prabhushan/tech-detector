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
            String lowerContent = content.toLowerCase();
            JsonNode registry = registryLoader.getRegistry();

            // Detect frameworks
            detectFromRegistry(registry, "frameworks", lowerContent, file, result::addFramework);

            // Detect cloud SDKs
            detectFromRegistry(registry, "cloud_sdks", lowerContent, file, result::addCloudSdk);

            // Detect databases
            detectFromRegistry(registry, "databases", lowerContent, file, result::addDatabase);

            // Detect AI/ML libraries
            if (registry.has("ai_ml")) {
                detectFromRegistry(registry, "ai_ml", lowerContent, file, result::addFramework);
            }

            // Detect vector databases
            if (registry.has("vector_databases")) {
                detectFromRegistry(registry, "vector_databases", lowerContent, file, result::addDatabase);
            }

            // Detect testing frameworks
            if (registry.has("testing")) {
                detectFromRegistry(registry, "testing", lowerContent, file, result::addFramework);
            }

            // Detect ORMs
            if (registry.has("orm")) {
                detectFromRegistry(registry, "orm", lowerContent, file, result::addFramework);
            }

            // Detect message queues
            if (registry.has("message_queue")) {
                detectFromRegistry(registry, "message_queue", lowerContent, file, result::addInfrastructure);
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
                    if (content.contains(indicatorStr)) {
                        String evidence = file.getFileName().toString() + " contains: " + indicatorStr;
                        adder.add(formatTechName(tech), evidence);
                        break; // Only add once per technology
                    }
                }
            }
        }
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
