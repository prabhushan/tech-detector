package com.example.detector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;

@SpringBootApplication(exclude = {
    ServletWebServerFactoryAutoConfiguration.class,
    DispatcherServletAutoConfiguration.class
})
public class TechDetectorApplication {
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(TechDetectorApplication.class);
        app.setWebApplicationType(org.springframework.boot.WebApplicationType.NONE);
        app.run(args);
    }
}
