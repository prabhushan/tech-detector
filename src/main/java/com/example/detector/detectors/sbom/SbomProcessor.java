package com.example.detector.detectors.sbom;

import com.example.detector.model.DetectionResult;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;

import java.util.List;
import java.util.Optional;

/**
 * Processes a CycloneDX Bom into DetectionResult using RegistryMatcher.
 */
@org.springframework.stereotype.Component
public class SbomProcessor {

    private final RegistryMatcher matcher;

    public SbomProcessor(RegistryMatcher matcher) {
        this.matcher = matcher;
    }

    /**
     * Populate detection result from a CycloneDX BOM.
     * Adds languages, frameworks, runtimes, cloudSdks, databases, containers.
     */
    public void processBom(Bom bom, DetectionResult result) {
        if (bom == null) return;

        List<Component> components = bom.getComponents();
        if (components != null) {
            for (Component c : components) {
                try {
                    String name = c.getName();
                    String version = c.getVersion();
                    String purl = c.getPurl(); // may be null
                    String type = (c.getType() != null) ? c.getType().toString() : null;

                    // 1) Language inference from PURL (safe null handling)
                    Optional<String> lang = Optional.empty();
                    if (purl != null) {
                        try {
                            lang = matcher.inferLanguageFromPurl(purl);
                        } catch (Exception ignored) {
                            lang = Optional.empty();
                        }
                    }
                    lang.ifPresent(result.languages::add);

                    // 2) Framework detection (matchFrameworks handles sbomMatch and keywords)
                    List<String> frameworks = matcher.matchFrameworks(name == null ? "" : name, purl);
                    for (String fw : frameworks) {
                        String evidence = buildEvidence(name, version, purl);
                        result.addFramework(fw, evidence);
                    }

                    // 3) Cloud SDKs
                    List<String> clouds = matcher.matchCloudSdks(name == null ? "" : name, purl);
                    for (String cl : clouds) {
                        String evidence = buildEvidence(name, version, purl);
                        result.addCloudSdk(cl, evidence);
                    }

                    // 4) Databases
                    List<String> dbs = matcher.matchDatabases(name == null ? "" : name, purl);
                    for (String db : dbs) {
                        String evidence = buildEvidence(name, version, purl);
                        result.addDatabase(db, evidence);
                    }

                    // 5) Containers (CycloneDX may mark components type=container)
                    if ("container".equalsIgnoreCase(type)) {
                        result.addInfrastructure("container", buildEvidence(name, version, purl));
                    }

                    // 6) Runtime heuristics from purl (simple)
                    if (purl != null) {
                        String plower = purl.toLowerCase();
                        if (plower.contains("openjdk") || plower.contains("jdk") || plower.contains("temurin") || plower.contains("corretto")) {
                            result.addRuntime("JDK", buildEvidence(name, version, purl));
                        } else if (plower.startsWith("pkg:pypi") || plower.contains("python")) {
                            result.addRuntime("Python", buildEvidence(name, version, purl));
                        } else if (plower.startsWith("pkg:npm") || plower.contains("node")) {
                            result.addRuntime("Node", buildEvidence(name, version, purl));
                        }
                    }
                } catch (Exception ex) {
                    // defensive per-component; continue
                }
            }
        }

        // Metadata tools may hint at build system / language
        if (bom.getMetadata() != null && bom.getMetadata().getTools() != null) {
            bom.getMetadata().getTools().forEach(tool -> {
                try {
                    String vendor = tool.getVendor() == null ? "" : tool.getVendor();
                    String tname = tool.getName() == null ? "" : tool.getName();
                    String combined = (vendor + " " + tname).toLowerCase();
                    if (combined.contains("maven") || combined.contains("gradle")) result.languages.add("Java");
                    if (combined.contains("pip") || combined.contains("poetry")) result.languages.add("Python");
                } catch (Exception ignored) {}
            });
        }
    }

    private String buildEvidence(String name, String version, String purl) {
        StringBuilder sb = new StringBuilder();
        if (name != null) sb.append(name);
        if (version != null) sb.append(":").append(version);
        if (purl != null) sb.append(" (").append(purl).append(")");
        return sb.toString();
    }
}
