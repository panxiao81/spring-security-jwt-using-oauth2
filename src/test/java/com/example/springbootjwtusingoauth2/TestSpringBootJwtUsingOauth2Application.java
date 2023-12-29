package com.example.springbootjwtusingoauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;

@TestConfiguration(proxyBeanMethods = false)
public class TestSpringBootJwtUsingOauth2Application {

    public static void main(String[] args) {
        SpringApplication.from(SpringBootJwtUsingOauth2Application::main).with(TestSpringBootJwtUsingOauth2Application.class).run(args);
    }

}
