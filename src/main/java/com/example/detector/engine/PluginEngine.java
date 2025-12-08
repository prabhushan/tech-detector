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
                    .filter(p -> !shouldExclude(p, projectRoot))
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

    private boolean shouldExclude(Path path, Path projectRoot) {
        Path relativePath = projectRoot.relativize(path);
        String pathStr = relativePath.toString().toLowerCase();

        // Exclude common build/config/cache directories
        return pathStr.startsWith("target/") || pathStr.startsWith("target\\") ||
               pathStr.startsWith("bin/") || pathStr.startsWith("bin\\") ||
               pathStr.startsWith("out/") || pathStr.startsWith("out\\") ||
               pathStr.startsWith(".git/") || pathStr.startsWith(".git\\") ||
               pathStr.startsWith(".settings/") || pathStr.startsWith(".settings\\") ||
               pathStr.startsWith("node_modules/") || pathStr.startsWith("node_modules\\") ||
               pathStr.startsWith("venv/") || pathStr.startsWith("venv\\") ||
               pathStr.startsWith("env/") || pathStr.startsWith("env\\") ||
               pathStr.startsWith(".venv/") || pathStr.startsWith(".venv\\") ||
               pathStr.startsWith("myenv/") || pathStr.startsWith("myenv\\") ||
               pathStr.startsWith("__pycache__/") || pathStr.startsWith("__pycache__\\") ||
               pathStr.startsWith("build/") || pathStr.startsWith("build\\") ||
               pathStr.startsWith("dist/") || pathStr.startsWith("dist\\") ||
               pathStr.startsWith(".idea/") || pathStr.startsWith(".idea\\") ||
               pathStr.startsWith(".vscode/") || pathStr.startsWith(".vscode\\") ||
               pathStr.startsWith(".gradle/") || pathStr.startsWith(".gradle\\") ||
               pathStr.startsWith(".classpath") || pathStr.startsWith(".factorypath") ||
               pathStr.startsWith(".project");
    }
}
