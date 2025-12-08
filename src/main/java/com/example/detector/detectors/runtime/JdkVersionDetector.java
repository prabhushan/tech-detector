package com.example.detector.detectors.runtime;

import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class JdkVersionDetector implements DetectorPlugin {
    private static final Pattern JAVA_VER_POM = Pattern.compile("<java.version>([^<]+)</java.version>|<maven\\.compiler\\.target>([^<]+)</maven\\.compiler\\.target>", Pattern.CASE_INSENSITIVE);
    private static final Pattern JAVA_DOCKER = Pattern.compile("FROM\\s+(openjdk|eclipse-temurin|amazoncorretto|adoptopenjdk|liberica|azul/zulu-openjdk)[:\\s]([^\\s]+)", Pattern.CASE_INSENSITIVE);

    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();
        if (!(name.equals("pom.xml") || name.equals("dockerfile") || name.startsWith("dockerfile") || name.endsWith(".gradle"))) return;
        try {
            String txt = FileUtils.readFileToString(file.toFile(), StandardCharsets.UTF_8);

            // Check for Java version in pom.xml or gradle files
            if (name.equals("pom.xml") || name.endsWith(".gradle")) {
                Matcher m = JAVA_VER_POM.matcher(txt);
                while (m.find()) {
                    String v = m.group(1);
                    if (v == null) v = m.group(2);
                    if (v != null) {
                        v = v.trim();
                        result.addRuntime("JDK", file.toString() + " -> " + v);
                        return;
                    }
                }
            }

            // Check for Java Docker images only
            if (name.equals("dockerfile") || name.startsWith("dockerfile")) {
                Matcher m = JAVA_DOCKER.matcher(txt);
                while (m.find()) {
                    String imageVersion = m.group(2);
                    if (imageVersion != null) {
                        imageVersion = imageVersion.trim();
                        // Extract numeric version (e.g., "17-jdk" -> "17")
                        String numeric = imageVersion.replaceAll("(\\d+).*", "$1");
                        result.addRuntime("JDK", file.toString() + " -> " + (numeric.isEmpty() ? imageVersion : numeric));
                        return;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
    }
}
