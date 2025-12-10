package com.example.detector.detectors.sbom;

import com.example.detector.model.DetectionResult;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

@org.springframework.stereotype.Component
public class SbomProcessor {
    private static final Logger log = LoggerFactory.getLogger(SbomProcessor.class);

    private final RegistryMatcher matcher;

    public SbomProcessor(RegistryMatcher matcher) {
        this.matcher = matcher;
    }

    /**
     * Populate detection result from a CycloneDX BOM.
     * Adds languages, frameworks, runtimes, cloudSdks, databases, containers.
     */
    public void processBom(Bom bom, DetectionResult result) {
        if (bom == null) {
            log.warn("BOM is null, skipping processing");
            return;
        }

        // Components present
        List<Component> components = bom.getComponents();
        if (components != null) {
            log.debug("Processing {} components from BOM", components.size());
            int processedCount = 0;
            for (Component c : components) {
                processedCount++;
                String name = c.getName();
                String version = c.getVersion();
                String purl = c.getPurl();
                String type = c.getType() != null ? c.getType().toString() : "";

                // language inference from purl
                Optional<String> lang = matcher.inferLanguageFromPurl(purl);
                lang.ifPresent(result.languages::add);

                // framework detection
                List<String> fwMatches = matcher.matchFrameworks(name + (version==null ? "" : ":"+version), purl);
                for (String fw : fwMatches) {
                    result.addFramework(fw, (name == null ? "" : name) + (version == null ? "" : ":" + version) + (purl == null ? "" : " ("+purl+")"));
                }

                // cloud SDKs
                List<String> clouds = matcher.matchCloudSdks(name, purl);
                for (String cName : clouds) {
                    result.addCloudSdk(cName, (name == null ? "" : name) + (version == null ? "" : ":"+version) + (purl == null ? "" : " ("+purl+")"));
                }

                // databases
                List<String> dbs = matcher.matchDatabases(name, purl);
                for (String db : dbs) {
                    result.addDatabase(db, (name == null ? "" : name) + (version == null ? "" : ":"+version));
                }

                // container components -> detect Docker/container base images
                if (type != null && type.equalsIgnoreCase("container")) {
                    result.addInfrastructure("container", (name == null ? "" : name) + (version == null ? "" : ":"+version));
                }

                // runtime heuristics from purl (e.g., pkg:generic/openjdk@17)
                if (purl != null) {
                    String lower = purl.toLowerCase();
                    if (lower.contains("openjdk") || lower.contains("jdk") || lower.contains("temurin") || lower.contains("corretto")) {
                        result.addRuntime("JDK", name + (version == null ? "" : ":" + version) + " (" + purl + ")");
                    } else if (lower.startsWith("pkg:pypi/") || lower.contains("python")) {
                        result.addRuntime("Python", name + (version == null ? "" : ":" + version));
                    } else if (lower.startsWith("pkg:npm/") || lower.contains("node")) {
                        result.addRuntime("Node", name + (version == null ? "" : ":" + version));
                    }
                }
            }
            log.debug("Processed {} components - Languages: {}, Frameworks: {}, Cloud SDKs: {}, Databases: {}", 
                     processedCount, result.languages.size(), result.frameworks.size(), 
                     result.cloudSdks.size(), result.databases.size());
        } else {
            log.debug("BOM has no components");
        }

        // Tool and metadata smell: BOM metadata may include tools/runtime info
        if (bom.getMetadata() != null) {
            if (bom.getMetadata().getTools() != null) {
                log.debug("Processing BOM metadata tools");
                bom.getMetadata().getTools().forEach(tool -> {
                    // tool.getVendor(), tool.getName() may hint at build system
                    String t = (tool.getVendor() == null ? "" : tool.getVendor()) + " " + (tool.getName() == null ? "" : tool.getName());
                    if (t.toLowerCase().contains("maven")) {
                        result.languages.add("Java");
                        log.debug("Detected Java from Maven tool in metadata");
                    }
                    if (t.toLowerCase().contains("gradle")) {
                        result.languages.add("Java");
                        log.debug("Detected Java from Gradle tool in metadata");
                    }
                });
            }
        }
        
        log.info("BOM processing completed - Languages: {}, Frameworks: {}, Runtimes: {}, Cloud SDKs: {}, Databases: {}, Infrastructure: {}", 
                result.languages.size(), result.frameworks.size(), result.runtimes.size(), 
                result.cloudSdks.size(), result.databases.size(), result.infrastructure.size());
    }
}
