package com.fyrp.urlguardx.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

@Service
public class UrlHausFeedService {

    private static final Logger log = LoggerFactory.getLogger(UrlHausFeedService.class);

    private static final String FEED_URL =
            "https://urlhaus.abuse.ch/downloads/csv/";

    // Exact URL match
    private final Set<String> maliciousUrls = new HashSet<>();

    // Domain-level match (NEW)
    private final Set<String> maliciousDomains = new HashSet<>();

    @PostConstruct
    public void loadFeed() {

        log.info("[URLHAUS] Downloading CSV threat feed...");

        int urlCount = 0;
        int domainCount = 0;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new URL(FEED_URL).openStream()))) {

            String line;

            while ((line = reader.readLine()) != null) {

                // Skip comments / metadata
                if (line.startsWith("#") || line.trim().isEmpty()) continue;

                String[] parts = line.split(",");

                if (parts.length > 2) {

                    String url = parts[2].replace("\"", "").trim();

                    if (url.isEmpty()) continue;

                    // 1️⃣ Exact URL storage
                    maliciousUrls.add(url);
                    urlCount++;

                    // 2️⃣ Domain extraction (NEW)
                    try {
                        String host = new URL(url).getHost();
                        if (host != null && !host.isBlank()) {
                            maliciousDomains.add(host.toLowerCase());
                            domainCount++;
                        }
                    } catch (Exception ignored) {
                        // ignore malformed URLs
                    }
                }
            }

            log.info("[URLHAUS] Loaded {} malicious URLs", urlCount);
            log.info("[URLHAUS] Loaded {} malicious domains", domainCount);

        } catch (Exception e) {
            log.error("[URLHAUS] Failed to load feed: {}", e.getMessage());
        }
    }

    // ─────────────────────────────────────────────
    // Exact URL check
    // ─────────────────────────────────────────────
    public boolean isMalicious(String url) {
        if (url == null || url.isBlank()) return false;
        return maliciousUrls.contains(url.trim());
    }

    // ─────────────────────────────────────────────
    // Domain-level check (NEW FEATURE)
    // ─────────────────────────────────────────────
    public boolean isMaliciousDomain(String url) {

        if (url == null || url.isBlank()) return false;

        try {
            if (!url.startsWith("http")) {
                url = "http://" + url;
            }

            String host = new URL(url).getHost();

            if (host == null) return false;

            return maliciousDomains.contains(host.toLowerCase());

        } catch (Exception e) {
            return false;
        }
    }
}