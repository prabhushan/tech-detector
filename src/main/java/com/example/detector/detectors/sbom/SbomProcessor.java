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

                    // Extract version from component or PURL
                    String effectiveVersion = version;
                    if ((effectiveVersion == null || effectiveVersion.isBlank()) && purl != null) {
                        effectiveVersion = extractVersionFromPurl(purl);
                    }

                    // 2) Framework detection (matchFrameworks handles sbomMatch and keywords)
                    List<String> frameworks = matcher.matchFrameworks(name == null ? "" : name, purl);
                    for (String fw : frameworks) {
                        String frameworkKey = appendVersionIfAvailable(fw, effectiveVersion);
                        String evidence = buildEvidence(name, version, purl);
                        result.addFramework(frameworkKey, evidence);
                    }

                    // 3) Cloud SDKs
                    List<String> clouds = matcher.matchCloudSdks(name == null ? "" : name, purl);
                    for (String cl : clouds) {
                        String cloudKey = appendVersionIfAvailable(cl, effectiveVersion);
                        String evidence = buildEvidence(name, version, purl);
                        result.addCloudSdk(cloudKey, evidence);
                    }

                    // 4) Databases
                    List<String> dbs = matcher.matchDatabases(name == null ? "" : name, purl);
                    for (String db : dbs) {
                        String dbKey = appendVersionIfAvailable(db, effectiveVersion);
                        String evidence = buildEvidence(name, version, purl);
                        result.addDatabase(dbKey, evidence);
                    }

                    // 5) Containers (CycloneDX may mark components type=container)
                    if ("container".equalsIgnoreCase(type)) {
                        result.addInfrastructure("container", buildEvidence(name, version, purl));
                    }

                    // 6) Runtime heuristics from purl (simple)
                    
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

    /**
     * Appends version to the key if version is available and not already present.
     * Returns "key:version" format if version exists, otherwise returns key as-is.
     */
    private String appendVersionIfAvailable(String key, String version) {
        if (version == null || version.isBlank()) {
            return key;
        }
        // Check if version is already in the key (avoid duplicates)
        if (key.contains(":")) {
            return key;
        }
        return key + ":" + version;
    }

    /**
     * Extracts version from PURL string.
     * PURL format: pkg:type/namespace/name@version?qualifiers#subpath
     * Returns version if found, null otherwise.
     */
    private String extractVersionFromPurl(String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }
        try {
            // Find @ symbol which precedes version
            int atIdx = purl.indexOf('@');
            if (atIdx < 0) {
                return null;
            }
            // Version ends at ? (qualifiers) or # (subpath) or end of string
            String afterAt = purl.substring(atIdx + 1);
            int qIdx = afterAt.indexOf('?');
            int hashIdx = afterAt.indexOf('#');
            int endIdx = afterAt.length();
            if (qIdx >= 0 && qIdx < endIdx) endIdx = qIdx;
            if (hashIdx >= 0 && hashIdx < endIdx) endIdx = hashIdx;
            
            String version = afterAt.substring(0, endIdx);
            return version.isBlank() ? null : version;
        } catch (Exception e) {
            return null;
        }
    }
}
