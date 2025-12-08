package com.example.detector.detectors.lang;

import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

@Component
public class PythonDetector implements DetectorPlugin {
    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();
        if (name.endsWith(".py") || name.equals("requirements.txt") || name.equals("pyproject.toml")) {
            result.languages.add("Python");
        }
    }
}
