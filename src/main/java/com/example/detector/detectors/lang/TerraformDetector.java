package com.example.detector.detectors.lang;

import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

@Component
public class TerraformDetector implements DetectorPlugin {
    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();
        if (name.endsWith(".tf") || name.endsWith(".tfvars")) {
            result.languages.add("Terraform");
            result.addInfrastructure("Terraform", file.toString());
        }
    }
}
