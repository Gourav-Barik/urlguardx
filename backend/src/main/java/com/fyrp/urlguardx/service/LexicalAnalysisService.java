package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Map;

@Service
public class LexicalAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(LexicalAnalysisService.class);

    private final WebClient webClient;
    @org.springframework.beans.factory.annotation.Value("${ML_SERVICE_URL}")
    private String mlServiceUrl;
    public LexicalAnalysisService(WebClient.Builder builder) {
        this.webClient = builder.build(); // remove baseUrl here
    }
    @org.springframework.cache.annotation.Cacheable(
            value = "mlCache",
            key = "#url"
    )
    public ModuleResult analyze(String url) {

        try {
            // Short-circuit for trusted domains BEFORE calling ML service
            if (isTrusted(url)) {
                return ModuleResult.clean(
                        "Trusted domain override — known legitimate domain",
                        5.0
                );
            }

            log.info("[LEXICAL-ML] Sending URL to ML service: {}", url);

            Map<String, Object> response = webClient.post()
                    .uri(mlServiceUrl + "/predict")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("url", url))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(60))  // 60s for Render cold-start
                    .block();

            if (response == null) {
                log.warn("[LEXICAL-ML] Response is null");
                return fallback(url);
            }

            int prediction = ((Number) response.get("prediction")).intValue();
            double confidence = ((Number) response.get("confidence")).doubleValue();

            log.info("[LEXICAL-ML] Prediction: {} | Confidence: {}", prediction, confidence);

            if (prediction == 1 && confidence >= 0.98) {
                return ModuleResult.danger(
                        "ML model detected strong phishing patterns",
                        confidence * 100
                );
            }

            if (prediction == 1 && confidence >= 0.80) {
                return ModuleResult.warning(
                        "ML model detected suspicious URL patterns",
                        confidence * 100
                );
            }

            return ModuleResult.clean(
                    "No significant phishing patterns detected",
                    confidence * 100
            );

        } catch (Exception e) {
            log.error("[LEXICAL-ML] ML service failed: {}", e.getMessage());
            return fallback(url);
        }
    }

    // 🔁 Fallback (VERY IMPORTANT)
    private ModuleResult fallback(String url) {

        log.warn("[LEXICAL-ML] Using fallback heuristic");

        if (url.matches("http[s]?://\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            return ModuleResult.warning(
                    "IP-based URL detected — potential phishing",
                    60
            );
        }

        if (url.contains("@") || url.contains("login")) {
            return ModuleResult.warning(
                    "Basic heuristic triggered (ML unavailable)",
                    40
            );
        }

        return ModuleResult.clean(
                "ML unavailable, no suspicious patterns detected",
                10
        );
    }

    private static final java.util.Set<String> SHORTENERS = java.util.Set.of(
            "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
            "adf.ly","bl.ink","rebrand.ly","short.io","tiny.cc","shorte.st"
    );

    public boolean isUrlShortener(String url) {
        try {
            if (!url.startsWith("http")) url = "http://" + url;
            String host = new java.net.URL(url).getHost();

            return SHORTENERS.stream()
                    .anyMatch(s -> host.equalsIgnoreCase(s) || host.endsWith("." + s));

        } catch (Exception e) {
            return false;
        }
    }
    private boolean isTrusted(String url) {
        return url.contains("google.com") ||
                url.contains("microsoft.com") ||
                url.contains("amazon.com")||
                url.contains("facebook.com")||
        url.contains("instagram.com") ||
        url.contains("github.com") ||
        url.contains("chatgpt.com") ;
    }
}