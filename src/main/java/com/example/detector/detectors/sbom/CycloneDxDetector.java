package com.example.detector.detectors.sbom;

import com.example.detector.model.DetectionResult;
import com.example.detector.spi.DetectorPlugin;
import org.cyclonedx.BomParserFactory;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;

@org.springframework.stereotype.Component
public class CycloneDxDetector implements DetectorPlugin {

    @Override
    public void inspect(Path file, Path projectRoot, DetectionResult result) {
        String name = file.getFileName().toString().toLowerCase();
        if (!(name.endsWith("bom.xml") || name.endsWith("cyclonedx.json") || name.endsWith("sbom.json"))) return;
        try (FileInputStream fis = new FileInputStream(file.toFile())) {
            // try json then xml
            try {
                JsonParser parser = new JsonParser();
                org.cyclonedx.model.Bom bom = parser.parse(fis);
                for (org.cyclonedx.model.Component c : bom.getComponents()) {
                    String purl = c.getPurl();
                    String cName = c.getName();
                    String v = c.getVersion();
                    if (purl != null && purl.toLowerCase().contains("spring")) {
                        result.addFramework("Spring Framework", cName + ":" + v + " (" + purl + ")");
                    }
                    if (purl != null && purl.toLowerCase().contains("python")) {
                        result.addRuntime("Python", cName + ":" + v);
                    }
                    if (purl != null && purl.toLowerCase().startsWith("pkg:docker/")) {
                        result.addInfrastructure("DockerImageSBOM", purl);
                    }
                }
                return;
            } catch (Exception ignore) {
                // try xml
            }
            try (FileInputStream fis2 = new FileInputStream(file.toFile())) {
                XmlParser parserXml = new XmlParser();
                org.cyclonedx.model.Bom bom = parserXml.parse(fis2);
                for (org.cyclonedx.model.Component c : bom.getComponents()) {
                    String purl = c.getPurl();
                    String cName = c.getName();
                    String v = c.getVersion();
                    if (purl != null && purl.toLowerCase().contains("spring")) {
                        result.addFramework("Spring Framework", cName + ":" + v + " (" + purl + ")");
                    }
                }
            } catch (Exception ex) {
                // ignore
            }
        } catch (Exception e) {
            // ignore
        }
    }
}
