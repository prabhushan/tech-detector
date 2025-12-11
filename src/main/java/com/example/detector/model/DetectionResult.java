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
    
    public List<NameVersion> finalResult = new ArrayList<>();

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
    
    public void populateFinalResult() {
        Set<NameVersion> unique = new LinkedHashSet<>();
        
        // Add languages (as NameVersion with version null)
        for (String lang : languages) {
            unique.add(new NameVersion(lang, null));
        }
        
        // Add frameworks, runtimes, infrastructure, cloudSdks, databases
        unique.addAll(extractNameVersion(frameworks));
        unique.addAll(extractNameVersion(runtimes));
        unique.addAll(extractNameVersion(infrastructure));
        unique.addAll(extractNameVersion(cloudSdks));
        unique.addAll(extractNameVersion(databases));
        
        finalResult = new ArrayList<>(unique);
    }
    
    private List<NameVersion> extractNameVersion(Map<String, List<String>> map) {
        Set<NameVersion> unique = new LinkedHashSet<>();
        for (String key : map.keySet()) {
            int colonIdx = key.indexOf(':');
            if (colonIdx > 0) {
                unique.add(new NameVersion(key.substring(0, colonIdx), key.substring(colonIdx + 1)));
            } else {
                unique.add(new NameVersion(key, null));
            }
        }
        return new ArrayList<>(unique);
    }
    
    public static class NameVersion {
        public String name;
        public String version;
        
        public NameVersion(String name, String version) {
            this.name = name;
            this.version = version;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            NameVersion that = (NameVersion) o;
            return Objects.equals(name, that.name) && Objects.equals(version, that.version);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(name, version);
        }
    }
}
