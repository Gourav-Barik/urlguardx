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
        if (!url.startsWith("http")) {
            url = "https://" + url;
        }

        // ✅ STEP 2 — Validate URL format and require a proper domain (with TLD)
        try {
            java.net.URL parsed = new java.net.URL(url);
            String host = parsed.getHost();
            // Reject bare hostnames with no dot (e.g. "google", "localhost")
            if (host == null || !host.contains(".")) {
                log.warn("[CONTROLLER] URL has no valid domain/TLD: {}", url);
                throw new IllegalArgumentException("URL must contain a valid domain name with a TLD (e.g. google.com)");
            }
            // Reject TLDs that are purely numeric (IP-like but malformed)
            String[] parts = host.split("\\.");
            String tld = parts[parts.length - 1];
            if (tld.matches("\\d+")) {
                log.warn("[CONTROLLER] URL has numeric TLD — not a domain name: {}", url);
                throw new IllegalArgumentException("URL must contain a valid domain name with a TLD (e.g. google.com)");
            }
        } catch (IllegalArgumentException iae) {
            throw iae; // re-throw our own validation errors
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