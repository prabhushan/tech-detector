package com.example.detector.cli;

import com.example.detector.engine.DetectorService;
import com.example.detector.model.DetectionResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Component
public class CliRunner implements CommandLineRunner {
    private static final Logger log = LoggerFactory.getLogger(CliRunner.class);
    
    private final DetectorService detectorService;
    private final ObjectMapper mapper = new ObjectMapper();

    public CliRunner(DetectorService detectorService) {
        this.detectorService = detectorService;
    }

    @Override
    public void run(String... args) throws Exception {
        log.info("Tech Detector CLI starting with {} argument(s)", args.length);
        
        if (args.length == 0) {
            log.warn("No arguments provided, showing usage");
            printUsage();
            System.exit(1);
            return;
        }

        List<Path> pathsToScan = new ArrayList<>();
        boolean prettyPrint = true;
        boolean aggregate = false;

        // Parse command-line arguments
        for (String arg : args) {
            if (arg.equals("--help") || arg.equals("-h")) {
                printUsage();
                System.exit(0);
                return;
            } else if (arg.equals("--compact") || arg.equals("-c")) {
                prettyPrint = false;
            } else if (arg.equals("--aggregate") || arg.equals("-a")) {
                aggregate = true;
            } else if (arg.startsWith("--path=")) {
                pathsToScan.add(Path.of(arg.substring("--path=".length())));
            } else if (!arg.startsWith("-")) {
                // Treat as a path if it doesn't start with -
                pathsToScan.add(Path.of(arg));
            }
        }

        if (pathsToScan.isEmpty()) {
            log.error("No project path specified in arguments");
            System.err.println("Error: No project path specified.");
            printUsage();
            System.exit(1);
            return;
        }

        log.info("Scanning {} path(s) - aggregate: {}, prettyPrint: {}", pathsToScan.size(), aggregate, prettyPrint);

        // Scan and output results
        if (aggregate && pathsToScan.size() == 1) {
            // Aggregate mode: scan all subdirectories
            Path rootPath = pathsToScan.get(0);
            if (!Files.exists(rootPath) || !Files.isDirectory(rootPath)) {
                log.error("Path must be a directory for aggregate mode: {}", rootPath);
                System.err.println("Error: Path must be a directory for aggregate mode: " + rootPath);
                System.exit(1);
                return;
            }

            log.info("Aggregate mode: scanning subdirectories in {}", rootPath);
            java.util.Map<String, DetectionResult> results = new java.util.LinkedHashMap<>();
            try {
                List<Path> children = Files.list(rootPath)
                    .filter(Files::isDirectory)
                    .toList();
                
                log.debug("Found {} subdirectories to scan", children.size());
                for (Path child : children) {
                    log.info("Scanning subdirectory: {}", child.getFileName());
                    results.put(child.getFileName().toString(), 
                               detectorService.scanProject(child));
                }
                log.info("Completed aggregate scan of {} subdirectories", children.size());
            } catch (Exception e) {
                log.error("Error scanning directory: {}", rootPath, e);
                System.err.println("Error scanning directory: " + e.getMessage());
                System.exit(1);
                return;
            }

            outputJson(results, prettyPrint);
        } else {
            // Single or multiple path mode
            if (pathsToScan.size() == 1) {
                Path path = pathsToScan.get(0);
                if (!Files.exists(path)) {
                    log.error("Path does not exist: {}", path);
                    System.err.println("Error: Path does not exist: " + path);
                    System.exit(1);
                    return;
                }
                log.info("Scanning single path: {}", path);
                DetectionResult result = detectorService.scanProject(path);
                log.info("Scan completed for path: {}", path);
                outputJson(result, prettyPrint);
            } else {
                // Multiple paths - output as map
                log.info("Scanning {} paths", pathsToScan.size());
                java.util.Map<String, DetectionResult> results = new java.util.LinkedHashMap<>();
                for (Path path : pathsToScan) {
                    if (Files.exists(path)) {
                        log.debug("Scanning path: {}", path);
                        results.put(path.toString(), detectorService.scanProject(path));
                    } else {
                        log.warn("Path does not exist, skipping: {}", path);
                        System.err.println("Warning: Path does not exist, skipping: " + path);
                    }
                }
                log.info("Completed scan of {} paths", results.size());
                outputJson(results, prettyPrint);
            }
        }

        log.info("Tech Detector CLI completed successfully");
        System.exit(0);
    }

    private void outputJson(Object result, boolean prettyPrint) throws Exception {
        if (prettyPrint) {
            System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result));
        } else {
            System.out.println(mapper.writeValueAsString(result));
        }
    }

    private void printUsage() {
        System.out.println("Tech Detector - SBOM-based technology detection tool");
        System.out.println();
        System.out.println("Usage: java -jar tech-detector.jar [OPTIONS] <path> [<path2> ...]");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  <path>                    Project directory or file path to scan");
        System.out.println("  --path=<path>             Alternative way to specify path");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -h, --help               Show this help message");
        System.out.println("  -c, --compact            Output compact JSON (no pretty printing)");
        System.out.println("  -a, --aggregate          Scan all subdirectories and aggregate results");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar tech-detector.jar /path/to/project");
        System.out.println("  java -jar tech-detector.jar --path=/path/to/project --compact");
        System.out.println("  java -jar tech-detector.jar --aggregate /path/to/multi-project-root");
        System.out.println("  java -jar tech-detector.jar /path/to/project1 /path/to/project2");
    }
}
