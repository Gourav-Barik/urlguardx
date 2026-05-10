package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.List;
import java.util.Map;

@Service
public class BlacklistCheckerService {

    private final UrlHausFeedService urlHausFeedService;
    private final WebClient webClient;

    private static final Logger log = LoggerFactory.getLogger(BlacklistCheckerService.class);

    @Value("${google.safe.api.key:}")
    private String googleApiKey;

    @Value("${google.safe.api.url:https://safebrowsing.googleapis.com/v4/threatMatches:find}")
    private String googleApiUrl;

    public BlacklistCheckerService(WebClient webClient,
                                   UrlHausFeedService urlHausFeedService) {
        this.webClient = webClient;
        this.urlHausFeedService = urlHausFeedService;
    }

    // ─────────────────────────────────────────────
    // MAIN FLOW (PRODUCTION SAFE)
    // ─────────────────────────────────────────────
    @org.springframework.cache.annotation.Cacheable(
            value = "threatCache",
            key = "#url"
    )
    public ModuleResult check(String url) {

        log.info("[BLACKLIST] Starting threat intelligence flow for: {}", url);
        log.info("[BLACKLIST] Flow: Google Safe Browsing → URLHaus Feed");

        // ─────────────────────────────────────────
        // STEP 1 — GOOGLE SAFE (PRIMARY)
        // ─────────────────────────────────────────
        boolean googleHit = false;

        try {
            googleHit = checkGoogleSafe(url);
        } catch (Exception e) {
            log.warn("[GOOGLE SAFE] Failed — fallback to URLHaus");
        }

        if (googleHit) {
            return ModuleResult.danger(
                    "Google Safe Browsing flagged this URL as phishing/malware.",
                    100.0
            );
        }

        // ─────────────────────────────────────────
        // STEP 2 — URLHAUS LOCAL FEED
        // ─────────────────────────────────────────
        try {

            // Exact match (strongest)
            if (urlHausFeedService.isMalicious(url)) {
                log.warn("[URLHAUS] Exact malicious URL detected");
                return ModuleResult.danger(
                        "Exact URL match found in URLHaus malware database.",
                        100.0
                );
            }

            // Domain-level match
            if (urlHausFeedService.isMaliciousDomain(url)) {
                log.warn("[URLHAUS] Malicious domain detected");
                return ModuleResult.danger(
                        "Domain flagged in URLHaus malware distribution network.",
                        90.0
                );
            }

            log.info("[URLHAUS] No match found (clean)");

        } catch (Exception e) {
            log.warn("[URLHAUS] Feed check failed — continuing safely");
        }

        // ─────────────────────────────────────────
        // FINAL CLEAN
        // ─────────────────────────────────────────
        return ModuleResult.clean(
                "No threats detected across Google Safe Browsing and URLHaus.",
                5.0
        );
    }

    // ─────────────────────────────────────────────
    // GOOGLE SAFE BROWSING
    // ─────────────────────────────────────────────
    private boolean checkGoogleSafe(String url) {

        if (googleApiKey == null || googleApiKey.isBlank()) {
            log.warn("[GOOGLE SAFE] API key missing — skipping");
            return false;
        }

        try {

            log.info("[GOOGLE SAFE] Checking URL: {}", url);

            String apiUrl = googleApiUrl + "?key=" + googleApiKey;

            Map<String, Object> body = Map.of(
                    "client", Map.of(
                            "clientId", "urlguardx",
                            "clientVersion", "1.0"
                    ),
                    "threatInfo", Map.of(
                            "threatTypes", List.of(
                                    "MALWARE",
                                    "SOCIAL_ENGINEERING",
                                    "UNWANTED_SOFTWARE"
                            ),
                            "platformTypes", List.of("ANY_PLATFORM"),
                            "threatEntryTypes", List.of("URL"),
                            "threatEntries", List.of(
                                    Map.of("url", url)
                            )
                    )
            );

            Map response = webClient.post()
                    .uri(apiUrl)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(5))   // ⏱ SAFE TIMEOUT
                    .block();

            boolean hit = response != null && response.containsKey("matches");

            if (hit) {
                log.warn("[GOOGLE SAFE] MALICIOUS URL detected");
            } else {
                log.info("[GOOGLE SAFE] URL is clean");
            }

            return hit;

        } catch (Exception e) {
            log.warn("[GOOGLE SAFE] API unavailable — {}", e.getMessage());
            return false;
        }
    }
}