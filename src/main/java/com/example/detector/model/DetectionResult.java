package com.example.detector.model;

import java.util.*;

public class DetectionResult {
    public String projectPath;
    public Set<String> languages = new TreeSet<>();
    public Map<String, List<String>> frameworks = new TreeMap<>();
    public Map<String, List<String>> runtimes = new TreeMap<>();
    public Map<String, List<String>> infrastructure = new TreeMap<>();
    public Map<String, List<String>> cloudSdks = new TreeMap<>();
    public Map<String, List<String>> databases = new TreeMap<>();
    public long scannedAt = System.currentTimeMillis();

    public void addFramework(String fw, String evidence) {
        frameworks.computeIfAbsent(fw, k -> new ArrayList<>()).add(evidence);
    }
    public void addRuntime(String rt, String evidence) {
        runtimes.computeIfAbsent(rt, k -> new ArrayList<>()).add(evidence);
    }
    public void addInfrastructure(String infra, String evidence) {
        infrastructure.computeIfAbsent(infra, k -> new ArrayList<>()).add(evidence);
    }
    public void addCloudSdk(String cloud, String evidence) {
        cloudSdks.computeIfAbsent(cloud, k -> new ArrayList<>()).add(evidence);
    }
    public void addDatabase(String db, String evidence) {
        databases.computeIfAbsent(db, k -> new ArrayList<>()).add(evidence);
    }
}
