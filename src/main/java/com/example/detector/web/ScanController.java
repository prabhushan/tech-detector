package com.example.detector.web;

import com.example.detector.engine.DetectorService;
import com.example.detector.model.DetectionResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final DetectorService detectorService;

    public ScanController(DetectorService detectorService) {
        this.detectorService = detectorService;
    }

    @GetMapping("/scan")
    public ResponseEntity<DetectionResult> scanProject(@RequestParam("path") String path) {
        DetectionResult res = detectorService.scanProject(Path.of(path));
        return ResponseEntity.ok(res);
    }

    @GetMapping("/aggregate")
    public ResponseEntity<Map<String, Object>> aggregate(@RequestParam("root") String root) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            Path rootPath = Path.of(root);
            java.util.List<Path> children = java.nio.file.Files.list(rootPath).filter(java.nio.file.Files::isDirectory).toList();
            for (Path p : children) {
                out.put(p.getFileName().toString(), detectorService.scanProject(p));
            }
        } catch (Exception ex) {
            out.put(root, detectorService.scanProject(Path.of(root)));
        }
        return ResponseEntity.ok(out);
    }
}
