package com.fyrp.urlguardx;

import org.springframework.boot.SpringApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@EnableCaching
@EnableRetry
@SpringBootApplication
public class UrlguardxApplication {

    public static void main(String[] args) {
        SpringApplication.run(UrlguardxApplication.class, args);
    }
}
