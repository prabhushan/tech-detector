package com.example.detector;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;

@Slf4j
@SpringBootApplication(exclude = {
    ServletWebServerFactoryAutoConfiguration.class,
    DispatcherServletAutoConfiguration.class
})
public class TechDetectorApplication {
    public static void main(String[] args) {
        log.info("TechDetectorApplication.main() called with {} argument(s)", args.length);
        for (int i = 0; i < args.length; i++) {
            log.info("  args[{}] = {}", i, args[i]);
        }
        SpringApplication app = new SpringApplication(TechDetectorApplication.class);
        app.setWebApplicationType(org.springframework.boot.WebApplicationType.NONE);
        app.run(args);
    }
}
