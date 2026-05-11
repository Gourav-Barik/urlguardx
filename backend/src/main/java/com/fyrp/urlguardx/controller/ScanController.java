package com.fyrp.urlguardx.controller;

import com.fyrp.urlguardx.dto.ScanRequest;
import com.fyrp.urlguardx.dto.ScanResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.fyrp.urlguardx.service.AgenticControllerService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * URLGuardX REST Controller
 * ──────────────────────────────────────────────────────────────────────────
 * Exposes the following endpoints:
 *
 *   POST /api/v1/scan          — Submit a URL for full agentic scanning
 *   GET  /api/v1/health        — Simple liveness probe
 */
@RestController
@RequestMapping("/api/v1")
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    private final AgenticControllerService agentService;

    public ScanController(AgenticControllerService agentService) {
        this.agentService = agentService;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  POST /api/v1/scan
    //  Body: { "url": "https://example.com" }
    //  Returns the full ScanResponse JSON consumed by the React frontend.
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping("/scan")
    public ResponseEntity<ScanResponse> scan(@Valid @RequestBody ScanRequest request) {

        String url = request.getUrl();

        log.info("[CONTROLLER] Scan request received for: {}", url);

        // ✅ STEP 1 — Normalize URL
        // Bare IPs default to http:// (browser behavior) so the SSL module can follow
        // redirect chains (e.g. 8.8.8.8 → https://dns.google/).
        // Bare domains default to https://.
        if (!url.startsWith("http")) {
            boolean isBareIp = url.split("/")[0].split(":")[0].matches("(\\d{1,3}\\.){3}\\d{1,3}");
            url = (isBareIp ? "http://" : "https://") + url;
        }

        // ✅ STEP 2 — Validate URL format: accept proper domains (with letter TLD) OR IPv4 addresses
        try {
            java.net.URL parsed = new java.net.URL(url);
            String host = parsed.getHost();

            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("URL must contain a valid host");
            }

            // Check if it's a valid IPv4 address (e.g. 8.8.8.8, 192.168.1.1)
            boolean isIPv4 = host.matches("(\\d{1,3}\\.){3}\\d{1,3}");

            if (!isIPv4) {
                // Domain name — must have a dot and a non-numeric TLD
                if (!host.contains(".")) {
                    log.warn("[CONTROLLER] Bare hostname with no dot: {}", url);
                    throw new IllegalArgumentException("URL must contain a valid domain name with a TLD or an IP address");
                }
                String[] parts = host.split("\\.");
                String tld = parts[parts.length - 1];
                if (tld.matches("\\d+")) {
                    log.warn("[CONTROLLER] Numeric TLD on non-IP host — malformed: {}", url);
                    throw new IllegalArgumentException("URL must contain a valid domain name with a TLD or an IP address");
                }
            } else {
                log.info("[CONTROLLER] IPv4 address accepted: {}", host);
            }
        } catch (IllegalArgumentException iae) {
            throw iae;
        } catch (Exception e) {
            log.warn("[CONTROLLER] Invalid URL received: {}", url);
            throw new IllegalArgumentException("Invalid URL format");
        }

        // ✅ STEP 3 — Call agentic service
        ScanResponse response = agentService.orchestrate(url);

        return ResponseEntity.ok(response);
    }

    // ─────────────────────────────────────────────────────────────────────
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {

        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "URLGuardX");
        health.put("timestamp", java.time.LocalDateTime.now().toString());

        return ResponseEntity.ok(health);
    }
}