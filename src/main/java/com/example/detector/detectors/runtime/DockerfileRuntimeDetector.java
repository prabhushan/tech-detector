package com.example.detector.detectors.runtime;

import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Component
public class DockerfileRuntimeDetector implements DetectorPlugin {
    private static final Pattern FROM = Pattern.compile("^FROM\\s+([^\\s]+)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();
        if (!name.startsWith("dockerfile")) {
            log.trace("Skipping file (not a Dockerfile): {}", file.getFileName());
            return;
        }
        
        log.info("DockerfileRuntimeDetector: Processing Dockerfile: {}", file);
        try {
            String txt = Files.readString(file, StandardCharsets.UTF_8);
            Matcher m = FROM.matcher(txt);
            if (m.find()) {
                String base = m.group(1);
                String lower = base.toLowerCase();
                log.info("DockerfileRuntimeDetector: Found FROM base image: {}", base);
                if (lower.contains("openjdk") || lower.contains("temurin") || lower.contains("corretto")) {
                    result.addRuntime("JDK", "Docker base: " + base);
                    log.info("DockerfileRuntimeDetector: Detected JDK runtime from Docker base: {}", base);
                } else if (lower.startsWith("python")) {
                    result.addRuntime("Python", "Docker base: " + base);
                    log.info("DockerfileRuntimeDetector: Detected Python runtime from Docker base: {}", base);
                } else if (lower.startsWith("node")) {
                    result.addRuntime("Node", "Docker base: " + base);
                    log.info("DockerfileRuntimeDetector: Detected Node runtime from Docker base: {}", base);
                }
                result.addInfrastructure("Docker", file.toString());
                log.info("DockerfileRuntimeDetector: Detected Docker infrastructure from: {}", file);
            } else {
                log.debug("DockerfileRuntimeDetector: No FROM instruction found in: {}", file);
            }
        } catch (Exception e) {
            log.warn("DockerfileRuntimeDetector: Error processing Dockerfile {}: {}", file, e.getMessage(), e);
        }
    }
}
