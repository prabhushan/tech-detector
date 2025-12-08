package com.example.detector.cli;

import com.example.detector.engine.DetectorService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

@Component
public class CliRunner implements CommandLineRunner {
    private final DetectorService detectorService;
    private final ObjectMapper mapper = new ObjectMapper();

    public CliRunner(DetectorService detectorService) {
        this.detectorService = detectorService;
    }

    @Override
    public void run(String... args) throws Exception {
        // If --scan.path is present, run CLI scan and exit
        for (String a : args) {
            if (a.startsWith("--scan.path=")) {
                String path = a.substring("--scan.path=".length());
                com.example.detector.model.DetectionResult res = detectorService.scanProject(Path.of(path));
                System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(res));
                System.exit(0);
            }
        }
        // else start server normally
    }
}
