package com.example.detector.detectors.framework;

import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Map;

@Component
public class PackageJsonDetector implements DetectorPlugin {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();
        if (!name.equals("package.json")) return;

        try {
            File packageJsonFile = file.toFile();
            JsonNode root = objectMapper.readTree(packageJsonFile);

            // Check dependencies and devDependencies
            JsonNode dependencies = root.get("dependencies");
            JsonNode devDependencies = root.get("devDependencies");

            // Detect Node.js runtime
            result.addRuntime("Node.js", "package.json detected");

            // Detect React
            if (hasDependency(dependencies, "react")) {
                String version = getDependencyVersion(dependencies, "react");
                result.addFramework("React", version);
                result.languages.add("JavaScript");
            }

            // Detect React Native
            if (hasDependency(dependencies, "react-native")) {
                String version = getDependencyVersion(dependencies, "react-native");
                result.addFramework("React Native", version);
            }

            // Detect Vue
            if (hasDependency(dependencies, "vue")) {
                String version = getDependencyVersion(dependencies, "vue");
                result.addFramework("Vue.js", version);
                result.languages.add("JavaScript");
            }

            // Detect Angular
            if (hasDependency(dependencies, "@angular/core")) {
                String version = getDependencyVersion(dependencies, "@angular/core");
                result.addFramework("Angular", version);
                result.languages.add("TypeScript");
            }

            // Detect Next.js
            if (hasDependency(dependencies, "next")) {
                String version = getDependencyVersion(dependencies, "next");
                result.addFramework("Next.js", version);
            }

            // Detect Redux
            if (hasDependency(dependencies, "redux") || hasDependency(dependencies, "@reduxjs/toolkit")) {
                String version = getDependencyVersion(dependencies, "@reduxjs/toolkit");
                if (version == null) {
                    version = getDependencyVersion(dependencies, "redux");
                }
                result.addFramework("Redux", version);
            }

            // Detect Express.js
            if (hasDependency(dependencies, "express")) {
                String version = getDependencyVersion(dependencies, "express");
                result.addFramework("Express.js", version);
            }

            // Detect NestJS
            if (hasDependency(dependencies, "@nestjs/core")) {
                String version = getDependencyVersion(dependencies, "@nestjs/core");
                result.addFramework("NestJS", version);
                result.languages.add("TypeScript");
            }

            // Detect UI Libraries
            if (hasDependency(dependencies, "antd")) {
                String version = getDependencyVersion(dependencies, "antd");
                result.addFramework("Ant Design", version);
            }

            if (hasDependency(dependencies, "@mui/material")) {
                String version = getDependencyVersion(dependencies, "@mui/material");
                result.addFramework("Material-UI", version);
            }

            // Detect Tailwind CSS
            if (hasDependency(dependencies, "tailwindcss") || hasDependency(devDependencies, "tailwindcss")) {
                String version = getDependencyVersion(dependencies, "tailwindcss");
                if (version == null) {
                    version = getDependencyVersion(devDependencies, "tailwindcss");
                }
                result.addFramework("Tailwind CSS", version);
            }

            // Detect Styled Components
            if (hasDependency(dependencies, "styled-components")) {
                String version = getDependencyVersion(dependencies, "styled-components");
                result.addFramework("Styled Components", version);
            }

            // Detect TypeScript
            if (hasDependency(dependencies, "typescript") || hasDependency(devDependencies, "typescript")) {
                result.languages.add("TypeScript");
            }

            // Detect GraphQL
            if (hasDependency(dependencies, "graphql")) {
                String version = getDependencyVersion(dependencies, "graphql");
                result.addFramework("GraphQL", version);
            }

            // Detect Apollo Client
            if (hasDependency(dependencies, "@apollo/client")) {
                String version = getDependencyVersion(dependencies, "@apollo/client");
                result.addFramework("Apollo Client", version);
            }

        } catch (Exception e) {
            // ignore
        }
    }

    private boolean hasDependency(JsonNode dependencies, String packageName) {
        return dependencies != null && dependencies.has(packageName);
    }

    private String getDependencyVersion(JsonNode dependencies, String packageName) {
        if (dependencies != null && dependencies.has(packageName)) {
            return dependencies.get(packageName).asText();
        }
        return null;
    }
}
