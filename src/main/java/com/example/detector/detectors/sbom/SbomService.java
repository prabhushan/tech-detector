package com.example.detector.detectors.sbom;

import lombok.extern.slf4j.Slf4j;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

@Slf4j
@Service
public class SbomService {

    /**
     * Parse a CycloneDX SBOM file (JSON) into a Bom object.
     * Returns null on parse error.
     * @throws IOException 
     * @throws ParseException 
     */
    public Bom parseBom(Path sbomFile) throws IOException, ParseException {
        log.info("Attempting to parse SBOM file: {}", sbomFile);
        try (InputStream in = Files.newInputStream(sbomFile)) {
            // Try JSON first
                log.debug("Trying JSON parser for SBOM file: {}", sbomFile);
                JsonParser jsonParser = new JsonParser();
                Bom bom = jsonParser.parse(in);
                log.info("Successfully parsed SBOM as JSON: {}", sbomFile);
                return bom;
            
        } 
    }
}
