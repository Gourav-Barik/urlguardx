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

        // ✅ STEP 2 — Validate URL format
        try {
            new java.net.URL(url);
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