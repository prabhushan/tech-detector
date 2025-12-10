package com.example.detector.engine;

import com.example.detector.model.DetectionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.file.Path;

@Service
public class DetectorService {
    private static final Logger log = LoggerFactory.getLogger(DetectorService.class);
    
    private final SbomFirstDetectorEngine engine;

    public DetectorService(SbomFirstDetectorEngine engine) { 
        this.engine = engine; 
    }

    public DetectionResult scanProject(Path projectRoot) {
        log.info("Starting project scan for: {}", projectRoot.toAbsolutePath());
        DetectionResult result = engine.scanProject(projectRoot);
        log.info("Project scan completed for: {} - Languages: {}, Frameworks: {}, Runtimes: {}", 
                projectRoot.toAbsolutePath(), 
                result.languages.size(), 
                result.frameworks.size(), 
                result.runtimes.size());
        return result;
    }
}
