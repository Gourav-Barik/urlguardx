package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URL;
import java.time.Duration;
import java.util.Map;
import java.util.Set;

@Service
public class LexicalAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(LexicalAnalysisService.class);

    private final WebClient webClient;

    @org.springframework.beans.factory.annotation.Value("${ML_SERVICE_URL}")
    private String mlServiceUrl;

    // ─────────────────────────────────────────────────────────────────────────
    // Trusted brand names (matched against the registered domain, TLD-agnostic)
    // e.g. "amazon" will match amazon.com, amazon.in, amazon.co.uk, etc.
    // ─────────────────────────────────────────────────────────────────────────
    private static final Set<String> TRUSTED_BRANDS = Set.of(
            "google", "microsoft", "amazon", "facebook", "instagram",
            "github", "chatgpt", "openai", "apple", "youtube",
            "twitter", "linkedin", "netflix", "spotify", "wikipedia",
            "yahoo", "bing", "reddit", "whatsapp", "paypal"
    );

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
            "adf.ly", "bl.ink", "rebrand.ly", "short.io", "tiny.cc", "shorte.st"
    );

    public LexicalAnalysisService(WebClient.Builder builder) {
        this.webClient = builder.build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Keep-alive ping — fires every 10 minutes to prevent Render cold-starts
    // ─────────────────────────────────────────────────────────────────────────
    @Scheduled(fixedDelay = 600_000) // 10 minutes
    public void pingMlService() {
        try {
            String result = webClient.get()
                    .uri(mlServiceUrl + "/health")
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(10))
                    .block();
            log.info("[LEXICAL-ML] Keep-alive ping OK: {}", result);
        } catch (Exception e) {
            log.warn("[LEXICAL-ML] Keep-alive ping failed (service may be cold): {}", e.getMessage());
        }
    }

    @org.springframework.cache.annotation.Cacheable(value = "mlCache", key = "#url")
    public ModuleResult analyze(String url) {

        try {
            // Short-circuit for trusted brands BEFORE calling ML service
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

    // ─────────────────────────────────────────────────────────────────────────
    // Fallback heuristics when ML service is unreachable
    // ─────────────────────────────────────────────────────────────────────────
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
                "ML unavailable; no suspicious patterns detected",
                10
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Trusted brand check — extracts hostname, strips subdomains,
    // then checks if the second-level domain matches a known brand.
    // This works for amazon.in, amazon.co.uk, google.co.in, etc.
    // ─────────────────────────────────────────────────────────────────────────
    private boolean isTrusted(String url) {
        try {
            if (!url.startsWith("http")) url = "https://" + url;
            String host = new URL(url).getHost().toLowerCase(); // e.g. "www.amazon.in"

            // Split host into parts: ["www", "amazon", "in"]
            String[] parts = host.split("\\.");

            // Check each part against known brands (covers SLD for most TLDs)
            for (String part : parts) {
                if (TRUSTED_BRANDS.contains(part)) {
                    log.info("[LEXICAL-ML] Trusted brand matched: '{}' in host '{}'", part, host);
                    return true;
                }
            }
        } catch (Exception e) {
            log.warn("[LEXICAL-ML] isTrusted() parse error: {}", e.getMessage());
        }
        return false;
    }

    public boolean isUrlShortener(String url) {
        try {
            if (!url.startsWith("http")) url = "http://" + url;
            String host = new URL(url).getHost();

            return SHORTENERS.stream()
                    .anyMatch(s -> host.equalsIgnoreCase(s) || host.endsWith("." + s));

        } catch (Exception e) {
            return false;
        }
    }
}