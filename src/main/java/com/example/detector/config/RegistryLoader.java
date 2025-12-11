package com.example.detector.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.InputStream;

@Slf4j
@Component
public class RegistryLoader {
    private final JsonNode registry;
    private final ObjectMapper mapper = new ObjectMapper();

    public RegistryLoader() {
        log.info("Loading technology registry from registry/registry.json");
        registry = loadRegistry();
        log.info("Technology registry loaded successfully");
    }

    private JsonNode loadRegistry() {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("registry/registry.json")) {
            if (in == null) {
                log.warn("Registry file not found at registry/registry.json, using empty registry");
                return mapper.createObjectNode();
            }
            JsonNode loaded = mapper.readTree(in);
            log.debug("Registry loaded - checking sections: frameworks, cloud_sdks, databases");
            return loaded;
        } catch (Exception ex) {
            log.error("Failed to load registry.json", ex);
            throw new RuntimeException("Failed to load registry.json", ex);
        }
    }

    public JsonNode getRegistry() { 
        return registry; 
    }
}
