package com.fyrp.urlguardx.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();

        // connection timeout (time to establish connection)
        factory.setConnectTimeout(3000);

        // read timeout (time to wait for response)
        factory.setReadTimeout(5000);

        return new RestTemplate(factory);
    }
}