package com.example.detector.engine;

import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.ServiceLoader;

@Component
public class PluginEngine {

    private final List<DetectorPlugin> plugins;

    public PluginEngine(List<DetectorPlugin> plugins) {
        this.plugins = plugins;
    }

    public DetectionResult scanProject(Path projectRoot) {
        DetectionResult result = new DetectionResult();
        result.projectPath = projectRoot.toAbsolutePath().toString();

        try {
            Files.walk(projectRoot)
                    .filter(Files::isRegularFile)
                    .limit(20000)
                    .forEach(p -> {
                        for (DetectorPlugin plugin : plugins) {
                            try {
                                plugin.inspect(p, projectRoot, result);
                            } catch (Exception e) {
                                // defensive: ignore plugin failures
                            }
                        }
                    });
        } catch (Exception e) {
            // swallow; in production log
        }
        return result;
    }
}
