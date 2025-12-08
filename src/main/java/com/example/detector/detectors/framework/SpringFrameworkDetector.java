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
                        result.addFramework("Spring Boot", parent.getVersion());
                    }
                } catch (Exception ex) {
                    // continue
                }
            }
        } catch (Exception ex) {
            // ignore
        }
    }
}
