package com.example.detector.engine;

import com.example.detector.model.DetectionResult;
import org.springframework.stereotype.Service;

import java.nio.file.Path;

@Service
public class DetectorService {
    private final PluginEngine engine;

    public DetectorService(PluginEngine engine) { this.engine = engine; }

    public DetectionResult scanProject(Path projectRoot) {
        return engine.scanProject(projectRoot);
    }
}
