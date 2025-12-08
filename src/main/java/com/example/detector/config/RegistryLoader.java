package com.example.detector.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.InputStream;

@Component
public class RegistryLoader {
    private final JsonNode registry;
    private final ObjectMapper mapper = new ObjectMapper();

    public RegistryLoader() {
        registry = loadRegistry();
    }

    private JsonNode loadRegistry() {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("registry/registry.json")) {
            if (in == null) return mapper.createObjectNode();
            return mapper.readTree(in);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to load registry.json", ex);
        }
    }

    public JsonNode getRegistry() { return registry; }
}
