package com.example.detector.detectors.sbom;

import com.example.detector.config.RegistryLoader;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RegistryMatcher - supports registry entries with fields:
 *  - keywords (array)
 *  - sbomMatch (array)
 *  - files (array)
 *  - match ("contains" | "exact" | "regex") default "contains"
 *
 * Provides purl-aware exact matching:
 *  - pattern can match namespace, name, namespace/name, namespace/name@version, or full purl
 */
@Component
public class RegistryMatcher {

    private final JsonNode registry;

    public RegistryMatcher(RegistryLoader loader) {
        this.registry = loader.getRegistry();
    }

    // Public API
    public List<String> matchFrameworks(String text, String purl) {
        return matchSection("frameworks", text, purl);
    }

    public List<String> matchCloudSdks(String text, String purl) {
        return matchSection("cloud_sdks", text, purl);
    }

    public List<String> matchDatabases(String text, String purl) {
        return matchSection("databases", text, purl);
    }

    public Optional<String> inferLanguageFromPurl(String purl) {
        if (purl == null) return Optional.empty();
        String lower = purl.toLowerCase(Locale.ROOT);
        if (lower.startsWith("pkg:maven") || lower.contains("maven") || lower.contains("pkg:gradle")) return Optional.of("Java");
        if (lower.startsWith("pkg:pypi") || lower.contains("pypi")) return Optional.of("Python");
        if (lower.startsWith("pkg:npm") || lower.contains("npm")) return Optional.of("JavaScript");
        if (lower.startsWith("pkg:golang") || lower.contains("golang")) return Optional.of("Go");
        if (lower.startsWith("pkg:nuget") || lower.contains("nuget")) return Optional.of("C#");
        if (lower.startsWith("pkg:gem") || lower.contains("gem")) return Optional.of("Ruby");
        if (lower.startsWith("pkg:cargo") || lower.contains("cargo")) return Optional.of("Rust");
        return Optional.empty();
    }

    // Internal helpers

    private List<String> matchSection(String sectionName, String text, String purl) {
        List<String> out = new ArrayList<>();
        JsonNode section = registry.path(sectionName);
        if (section.isMissingNode() || !section.isObject()) return out;

        String hay = ( (text == null ? "" : text) + " " + (purl == null ? "" : purl) ).toLowerCase(Locale.ROOT);

        Iterator<String> it = section.fieldNames();
        while (it.hasNext()) {
            String key = it.next();
            JsonNode node = section.get(key);
            if (node == null || node.isMissingNode()) continue;

            String defaultMatch = node.path("match").asText("contains").toLowerCase(Locale.ROOT);

            boolean matched = false;

            // 1) keywords
            JsonNode keywords = node.path("keywords");
            if (keywords.isArray()) {
                for (JsonNode kw : keywords) {
                    if (kw.isTextual()) {
                        if (applyMatch(hay, kw.asText(), defaultMatch, purl)) {
                            out.add(key);
                            matched = true;
                            break;
                        }
                    }
                }
            }
            if (matched) continue;

            // 2) sbomMatch
            JsonNode sboms = node.path("sbomMatch");
            if (sboms.isArray()) {
                for (JsonNode s : sboms) {
                    if (s.isTextual()) {
                        if (applyMatch(hay, s.asText(), defaultMatch, purl)) {
                            out.add(key);
                            matched = true;
                            break;
                        }
                    }
                }
            }
            if (matched) continue;

            // 3) files (match file names / dockerfile entries if needed)
            JsonNode files = node.path("files");
            if (files.isArray()) {
                for (JsonNode f : files) {
                    if (f.isTextual()) {
                        if (applyMatch(hay, f.asText(), defaultMatch, purl)) {
                            out.add(key);
                            matched = true;
                            break;
                        }
                    }
                }
            }
        }

        return dedupePreserveOrder(out);
    }

    /**
     * Apply a single pattern with the configured match type against haystack and purl.
     * matchType: contains (default), exact, regex
     */
    private boolean applyMatch(String hayLower, String rawPattern, String matchType, String purl) {
        if (rawPattern == null || rawPattern.isBlank()) return false;

        String patternLower = rawPattern.toLowerCase(Locale.ROOT);
        matchType = (matchType == null) ? "contains" : matchType.toLowerCase(Locale.ROOT);

        switch (matchType) {
            case "exact":
                // Exact should compare against purl components (namespace/name, namespace, name, full purl),
                // or against the haystack full string.
                if (purl != null && purlMatchesExact(patternLower, purl)) return true;
                // fallback: full hay equality (rare)
                return hayLower.trim().equals(patternLower);

            case "regex":
                try {
                    Pattern p = Pattern.compile(rawPattern, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
                    Matcher m = p.matcher(hayLower);
                    return m.find();
                } catch (Exception ex) {
                    // malformed regex => fallback to contains
                    return hayLower.contains(patternLower);
                }

            case "contains":
            default:
                return hayLower.contains(patternLower);
        }
    }

    /**
     * Matches pattern exactly against PURL components:
     * supports matching:
     *   - full purl: "pkg:maven/org.springframework.boot/spring-boot-starter@3.5.0"
     *   - namespace only: "org.springframework.boot"
     *   - name only: "spring-boot-starter-actuator"
     *   - namespace/name: "org.springframework.boot/spring-boot-starter-actuator"
     *   - namespace/name@version: "org.springframework.boot/spring-boot-starter-actuator@3.5.0"
     */
    private boolean purlMatchesExact(String patternLower, String purl) {
        if (purl == null || purl.isBlank()) return false;
        PurlParts parts = parsePurl(purl);
        if (parts == null) return false;

        // full purl (normalized lower-case)
        String normalizedPurl = parts.original.toLowerCase(Locale.ROOT);

        if (patternLower.equals(normalizedPurl)) return true;

        // namespace only
        if (parts.namespace != null && patternLower.equals(parts.namespace.toLowerCase(Locale.ROOT))) return true;

        // name only
        if (parts.name != null && patternLower.equals(parts.name.toLowerCase(Locale.ROOT))) return true;

        // namespace/name
        if (parts.namespace != null && parts.name != null) {
            String nsName = (parts.namespace + "/" + parts.name).toLowerCase(Locale.ROOT);
            if (patternLower.equals(nsName)) return true;

            // namespace/name@version
            if (parts.version != null) {
                String nsNameVer = nsName + "@" + parts.version.toLowerCase(Locale.ROOT);
                if (patternLower.equals(nsNameVer)) return true;
            }
        }

        // as last resort, check if pattern equals purl type or purl type + ":" + namespace
        if (parts.type != null && patternLower.equals(parts.type.toLowerCase(Locale.ROOT))) return true;
        if (parts.type != null && parts.namespace != null) {
            String tNs = (parts.type + ":" + parts.namespace).toLowerCase(Locale.ROOT);
            if (patternLower.equals(tNs)) return true;
        }

        return false;
    }

    private PurlParts parsePurl(String purl) {
        if (purl == null) return null;
        // Typical PURL: pkg:type/namespace/name@version?qualifiers#subpath
        // We'll do a simple conservative parse
        try {
            String working = purl.trim();
            if (working.startsWith("pkg:")) working = working.substring(4);
            String type = null, namespace = null, name = null, version = null;
            int qIdx = working.indexOf('?');
            if (qIdx >= 0) working = working.substring(0, qIdx);
            int hashIdx = working.indexOf('#');
            if (hashIdx >= 0) working = working.substring(0, hashIdx);

            // split version
            int atIdx = working.indexOf('@');
            if (atIdx >= 0) {
                version = working.substring(atIdx + 1);
                working = working.substring(0, atIdx);
            }

            // first slash divides type and the rest
            int firstSlash = working.indexOf('/');
            if (firstSlash > 0) {
                type = working.substring(0, firstSlash);
                String rest = working.substring(firstSlash + 1);
                // rest may contain multiple path segments: namespace/name OR name only OR namespace/name/subpath
                // We'll treat last segment as name, preceeding as namespace
                int lastSlash = rest.lastIndexOf('/');
                if (lastSlash >= 0) {
                    namespace = rest.substring(0, lastSlash);
                    name = rest.substring(lastSlash + 1);
                } else {
                    name = rest;
                }
            } else {
                // no slash - weird but capture as name
                name = working;
            }

            return new PurlParts(purl, type, namespace, name, version);
        } catch (Exception ex) {
            return null;
        }
    }

    private List<String> dedupePreserveOrder(List<String> in) {
        LinkedHashSet<String> set = new LinkedHashSet<>(in);
        return new ArrayList<>(set);
    }

    // Helper container
    private static final class PurlParts {
        final String original;
        final String type;
        final String namespace;
        final String name;
        final String version;
        PurlParts(String original, String type, String namespace, String name, String version) {
            this.original = original;
            this.type = type;
            this.namespace = namespace;
            this.name = name;
            this.version = version;
        }
    }
}
