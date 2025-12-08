package com.example.detector.spi;

import com.example.detector.model.DetectionResult;

import java.nio.file.Path;

public interface DetectorPlugin {
    /**
     * Inspect a file and update DetectionResult with findings (language/framework/runtime).
     * Implementations should be defensive and not throw.
     *
     * @param file the file being inspected
     * @param projectRoot root path of the scanned project
     * @param result the aggregator to update
     */
    void inspect(Path file, Path projectRoot, DetectionResult result);
}
