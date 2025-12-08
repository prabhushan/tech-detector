package com.example.detector.detectors.framework;

import com.example.detector.config.RegistryLoader;
import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import org.apache.commons.io.FileUtils;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.Parent;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.springframework.stereotype.Component;

import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

@Component
public class SpringFrameworkDetector implements DetectorPlugin {

    private final RegistryLoader registryLoader;

    public SpringFrameworkDetector(RegistryLoader registryLoader) {
        this.registryLoader = registryLoader;
    }

    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();
        try {
            if (name.equals("pom.xml")) {
                // use maven-model to parse
                try (FileReader fr = new FileReader(file.toFile())) {
                    Model model = new MavenXpp3Reader().read(fr);
                    Parent parent = model.getParent();
                    if (parent != null && parent.getGroupId() != null && parent.getGroupId().contains("org.springframework.boot")) {
                        result.addFramework("Spring Boot", file.toString() + " parent:" + parent.getVersion());
                    }
                    List<Dependency> deps = model.getDependencies();
                    for (Dependency d : deps) {
                        String g = d.getGroupId() != null ? d.getGroupId() : "";
                        String a = d.getArtifactId() != null ? d.getArtifactId() : "";
                        if (g.contains("org.springframework") || a.contains("spring")) {
                            String evidence = d.getGroupId() + ":" + d.getArtifactId() + ":" + d.getVersion();
                            result.addFramework("Spring Framework", evidence);
                        }
                    }
                } catch (Exception ex) {
                    // continue
                }
            } else {
                // scan file content for simple spring indicators
                long size = file.toFile().length();
                String txt = "";
                if (size < 200_000) {
                    txt = FileUtils.readFileToString(file.toFile(), StandardCharsets.UTF_8);
                } else {
                    // Read first 32KB for large files
                    byte[] buffer = new byte[32 * 1024];
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(file.toFile())) {
                        int bytesRead = fis.read(buffer);
                        txt = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
                    }
                }
                String lower = txt.toLowerCase();
                if (lower.contains("org.springframework") || lower.contains("spring-boot")) {
                    result.addFramework("Spring Framework", file.toString());
                }
            }
        } catch (Exception ex) {
            // ignore
        }
    }
}
