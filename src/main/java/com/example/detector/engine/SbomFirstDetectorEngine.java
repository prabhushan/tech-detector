package com.example.detector.engine;

import com.example.detector.model.DetectionResult;
import com.example.detector.detectors.sbom.SbomProcessor;
import com.example.detector.detectors.sbom.SbomService;
import com.example.detector.spi.DetectorPlugin;
import org.cyclonedx.model.Bom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@Component
public class SbomFirstDetectorEngine {
    private static final Logger log = LoggerFactory.getLogger(SbomFirstDetectorEngine.class);

    private final SbomService sbomService;
    private final SbomProcessor sbomProcessor;
    private final List<DetectorPlugin> plugins;

    public SbomFirstDetectorEngine(SbomService sbomService, SbomProcessor sbomProcessor, List<DetectorPlugin> plugins) {
        this.sbomService = sbomService;
        this.sbomProcessor = sbomProcessor;
        this.plugins = plugins;
        log.info("SbomFirstDetectorEngine initialized with {} plugin(s)", plugins.size());
    }

    /**
     * Scan a project root with SBOM-first approach.
     */
    public DetectionResult scanProject(Path projectRoot) {
        DetectionResult result = new DetectionResult();
        result.projectPath = projectRoot.toAbsolutePath().toString();
        log.debug("Starting SBOM-first scan for project: {}", result.projectPath);

        try {
            // 1) find SBOM files in the project root (shallow)
            Optional<Path> sbomFile = findSbomFile(projectRoot);
            if (sbomFile.isPresent()) {
                log.info("Found SBOM file: {}", sbomFile.get().getFileName());
                Bom bom = sbomService.parseBom(sbomFile.get());
                if (bom != null) {
                    log.debug("Successfully parsed SBOM, processing components");
                    sbomProcessor.processBom(bom, result);
                    log.debug("Processed SBOM - Languages: {}, Frameworks: {}, Components processed", 
                              result.languages.size(), result.frameworks.size());
                } else {
                    log.warn("Failed to parse SBOM file: {}", sbomFile.get());
                }
            } else {
                log.debug("No SBOM file found in project root: {}", projectRoot);
            }

            // 2) if SBOM gave us languages and frameworks / runtimes then we are mostly done.
            boolean hasLanguage = !result.languages.isEmpty();
            boolean hasFramework = !result.frameworks.isEmpty() || !result.runtimes.isEmpty() || !result.infrastructure.isEmpty();
            log.debug("SBOM analysis result - Has language: {}, Has framework: {}", hasLanguage, hasFramework);

            // 3) fallback: if missing, run file-based plugin detectors (best-effort)
            if (!hasLanguage || !hasFramework) {
                log.info("SBOM analysis incomplete, falling back to file-based detection");
                // shallow walk and apply plugins
                try (Stream<Path> stream = Files.walk(projectRoot)) {
                    long fileCount = stream.filter(Files::isRegularFile)
                          .limit(20000)
                          .peek(p -> {
                              for (DetectorPlugin plugin : plugins) {
                                  try {
                                      plugin.inspect(p, projectRoot, result);
                                  } catch (Exception e) {
                                      log.debug("Plugin {} failed for file {}: {}", plugin.getClass().getSimpleName(), p, e.getMessage());
                                  }
                              }
                          })
                          .count();
                    log.debug("File-based detection completed - scanned {} files", fileCount);
                } catch (Exception e) {
                    log.error("Error during file-based detection", e);
                }
            } else {
                log.info("SBOM analysis sufficient, skipping file-based detection");
            }

        } catch (Exception e) {
            log.error("Error during SBOM-first scan, falling back to file-based detection", e);
            // fail-safe: fallback file-scan if SBOM parse failed
            try (Stream<Path> stream = Files.walk(projectRoot)) {
                long fileCount = stream.filter(Files::isRegularFile).limit(20000).peek(p -> {
                    for (DetectorPlugin plugin : plugins) {
                        try { 
                            plugin.inspect(p, projectRoot, result); 
                        } catch (Exception ex) {
                            log.debug("Plugin {} failed for file {}: {}", plugin.getClass().getSimpleName(), p, ex.getMessage());
                        }
                    }
                }).count();
                log.info("Fallback file-based detection completed - scanned {} files", fileCount);
            } catch (Exception ex) {
                log.error("Error during fallback file-based detection", ex);
            }
        }

        log.debug("Scan completed - Languages: {}, Frameworks: {}, Runtimes: {}, Infrastructure: {}", 
                 result.languages.size(), result.frameworks.size(), result.runtimes.size(), result.infrastructure.size());
        return result;
    }

    private Optional<Path> findSbomFile(Path root) {
        try (Stream<Path> s = Files.list(root)) {
            Optional<Path> found = s.filter(Files::isRegularFile)
                    .filter(p -> {
                        String n = p.getFileName().toString().toLowerCase();
                        return n.equals("bom.xml") ||
                               n.startsWith("cyclonedx") && (n.endsWith(".json") || n.endsWith(".xml")) ||
                               n.equals("sbom.json") ||
                               n.equals("cyclonedx.json");
                    }).findFirst();
            if (found.isPresent()) {
                log.debug("Found SBOM file: {} in directory: {}", found.get().getFileName(), root);
            }
            return found;
        } catch (Exception e) {
            log.debug("Error listing files in directory {}: {}", root, e.getMessage());
            return Optional.empty();
        }
    }
}
