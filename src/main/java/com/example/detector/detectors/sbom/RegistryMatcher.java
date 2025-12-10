package com.example.detector.detectors.sbom;

import com.example.detector.config.RegistryLoader;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class RegistryMatcher {
    private static final Logger log = LoggerFactory.getLogger(RegistryMatcher.class);

    private final JsonNode registry;

    public RegistryMatcher(RegistryLoader loader) {
        this.registry = loader.getRegistry();
        log.debug("RegistryMatcher initialized with registry loaded");
    }

    /**
     * Return matching framework keys for a given purl/name/text
     */
    public List<String> matchFrameworks(String text, String purl) {
        List<String> out = new ArrayList<>();
        JsonNode frameworks = registry.path("frameworks");
        if (frameworks.isMissingNode()) {
            log.debug("No frameworks section found in registry");
            return out;
        }

        String hay = (purl == null ? "" : purl.toLowerCase()) + " " + (text == null ? "" : text.toLowerCase());
        frameworks.fieldNames().forEachRemaining(fwKey -> {
            JsonNode node = frameworks.get(fwKey);
            JsonNode inds = node.path("indicators");
            if (!inds.isMissingNode()) {
                for (JsonNode ind : inds) {
                    String s = ind.asText().toLowerCase();
                    if (!s.isEmpty() && hay.contains(s)) {
                        out.add(fwKey);
                        break;
                    }
                }
            }
            // check pomArtifacts or sbomIdentifiers if present
            JsonNode pids = node.path("sbomIdentifiers");
            if (!pids.isMissingNode()) {
                for (JsonNode pid : pids) {
                    String s = pid.asText().toLowerCase();
                    if (!s.isEmpty() && hay.contains(s)) {
                        if (!out.contains(fwKey)) out.add(fwKey);
                        break;
                    }
                }
            }
        });
        return out;
    }

    public List<String> matchCloudSdks(String text, String purl) {
        List<String> out = new ArrayList<>();
        JsonNode cloud = registry.path("cloud_sdks");
        if (cloud.isMissingNode()) {
            log.debug("No cloud_sdks section found in registry");
            return out;
        }
        String hay = (purl == null ? "" : purl.toLowerCase()) + " " + (text == null ? "" : text.toLowerCase());
        cloud.fieldNames().forEachRemaining(cn -> {
            JsonNode node = cloud.get(cn);
            JsonNode inds = node.path("indicators");
            if (!inds.isMissingNode()) {
                for (JsonNode ind : inds) {
                    String s = ind.asText().toLowerCase();
                    if (!s.isEmpty() && hay.contains(s)) {
                        out.add(cn);
                        break;
                    }
                }
            }
        });
        if (!out.isEmpty()) {
            log.debug("Matched {} cloud SDK(s) for text: {}, purl: {}", out.size(), text, purl);
        }
        return out;
    }

    public List<String> matchDatabases(String text, String purl) {
        List<String> out = new ArrayList<>();
        JsonNode dbs = registry.path("databases");
        if (dbs.isMissingNode()) {
            log.debug("No databases section found in registry");
            return out;
        }
        String hay = (purl == null ? "" : purl.toLowerCase()) + " " + (text == null ? "" : text.toLowerCase());
        dbs.fieldNames().forEachRemaining(db -> {
            JsonNode node = dbs.get(db);
            JsonNode inds = node.path("indicators");
            if (!inds.isMissingNode()) {
                for (JsonNode ind : inds) {
                    String s = ind.asText().toLowerCase();
                    if (!s.isEmpty() && hay.contains(s)) {
                        out.add(db);
                        break;
                    }
                }
            }
        });
        if (!out.isEmpty()) {
            log.debug("Matched {} database(s) for text: {}, purl: {}", out.size(), text, purl);
        }
        return out;
    }

    public Optional<String> inferLanguageFromPurl(String purl) {
        if (purl == null) {
            log.debug("PURL is null, cannot infer language");
            return Optional.empty();
        }
        String lower = purl.toLowerCase();
        if (lower.startsWith("pkg:maven") || lower.contains("maven")) {
            log.debug("Inferred language: Java from PURL: {}", purl);
            return Optional.of("Java");
        }
        if (lower.startsWith("pkg:pypi") || lower.contains("pypi")) {
            log.debug("Inferred language: Python from PURL: {}", purl);
            return Optional.of("Python");
        }
        if (lower.startsWith("pkg:npm") || lower.contains("npm")) {
            log.debug("Inferred language: JavaScript from PURL: {}", purl);
            return Optional.of("JavaScript");
        }
        if (lower.startsWith("pkg:golang") || lower.contains("golang")) {
            log.debug("Inferred language: Go from PURL: {}", purl);
            return Optional.of("Go");
        }
        if (lower.startsWith("pkg:nuget") || lower.contains("nuget")) {
            log.debug("Inferred language: C# from PURL: {}", purl);
            return Optional.of("C#");
        }
        if (lower.startsWith("pkg:gem") || lower.contains("gem")) {
            log.debug("Inferred language: Ruby from PURL: {}", purl);
            return Optional.of("Ruby");
        }
        if (lower.startsWith("pkg:cargo") || lower.contains("cargo")) {
            log.debug("Inferred language: Rust from PURL: {}", purl);
            return Optional.of("Rust");
        }
        log.debug("Could not infer language from PURL: {}", purl);
        return Optional.empty();
    }
}
