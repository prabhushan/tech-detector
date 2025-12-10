package com.example.detector.detectors.sbom;

import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

@Service
public class SbomService {
    private static final Logger log = LoggerFactory.getLogger(SbomService.class);

    /**
     * Parse a CycloneDX SBOM file (JSON or XML) into a Bom object.
     * Returns null on parse error.
     */
    public Bom parseBom(Path sbomFile) {
        log.info("Attempting to parse SBOM file: {}", sbomFile);
        try (InputStream in = Files.newInputStream(sbomFile)) {
            // Try JSON first
            try {
                log.debug("Trying JSON parser for SBOM file: {}", sbomFile);
                JsonParser jsonParser = new JsonParser();
                Bom bom = jsonParser.parse(in);
                log.info("Successfully parsed SBOM as JSON: {}", sbomFile);
                return bom;
            } catch (Exception e) {
                log.debug("JSON parsing failed for {}, trying XML parser: {}", sbomFile, e.getMessage());
                // If JSON parsing fails, try XML
                try (InputStream xmlIn = Files.newInputStream(sbomFile)) {
                    XmlParser xmlParser = new XmlParser();
                    Bom bom = xmlParser.parse(xmlIn);
                    log.info("Successfully parsed SBOM as XML: {}", sbomFile);
                    return bom;
                } catch (Exception ex) {
                    log.error("Failed to parse SBOM file as both JSON and XML: {}", sbomFile, ex);
                    return null;
                }
            }
        } catch (Exception e) {
            log.error("Error reading SBOM file: {}", sbomFile, e);
            return null;
        }
    }
}
