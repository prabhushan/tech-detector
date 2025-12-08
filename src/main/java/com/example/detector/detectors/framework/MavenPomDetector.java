package com.example.detector.detectors.framework;

import com.example.detector.config.RegistryLoader;
import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.springframework.stereotype.Component;

import java.io.FileReader;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.List;

@Component
public class MavenPomDetector implements DetectorPlugin {

    private final RegistryLoader registryLoader;

    public MavenPomDetector(RegistryLoader registryLoader) {
        this.registryLoader = registryLoader;
    }

    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();

        if (!name.equals("pom.xml")) {
            return;
        }

        try (FileReader fr = new FileReader(file.toFile())) {
            Model model = new MavenXpp3Reader().read(fr);
            List<Dependency> deps = model.getDependencies();
            JsonNode registry = registryLoader.getRegistry();

            for (Dependency dep : deps) {
                String groupId = dep.getGroupId() != null ? dep.getGroupId() : "";
                String artifactId = dep.getArtifactId() != null ? dep.getArtifactId() : "";
                String version = dep.getVersion() != null ? dep.getVersion() : "";
                String fullDep = groupId.toLowerCase() + ":" + artifactId.toLowerCase();

                // Check cloud SDKs
                checkCategory(registry, "cloud_sdks", fullDep, groupId, artifactId, version, result::addCloudSdk);

                // Check databases
                checkCategory(registry, "databases", fullDep, groupId, artifactId, version, result::addDatabase);
            }
        } catch (Exception ex) {
            // ignore
        }
    }

    private void checkCategory(JsonNode registry, String category, String fullDep,
                               String groupId, String artifactId, String version, ResultAdder adder) {
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

                    if (fullDep.contains(indicatorStr) || groupId.contains(indicatorStr) || artifactId.contains(indicatorStr)) {
                        String evidence = groupId + ":" + artifactId + (version.isEmpty() ? "" : ":" + version);
                        adder.add(formatTechName(tech), evidence);
                        break;
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
