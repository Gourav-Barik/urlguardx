package com.fyrp.urlguardx.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class UrlHausFeedService {

    private static final Logger log = LoggerFactory.getLogger(UrlHausFeedService.class);

    private static final String FEED_URL =
            "https://urlhaus.abuse.ch/downloads/csv/";

    // Thread-safe sets (written by background thread, read by request threads)
    private final Set<String> maliciousUrls    = Collections.synchronizedSet(new HashSet<>());
    private final Set<String> maliciousDomains = Collections.synchronizedSet(new HashSet<>());

    // True once the feed has been successfully loaded
    private final AtomicBoolean feedReady = new AtomicBoolean(false);

    /**
     * Kick off the UrlHaus feed download in a background daemon thread so it does
     * NOT block Spring's main startup thread. Tomcat binds its port immediately and
     * the threat feed becomes available within ~10 s of startup.
     */
    @PostConstruct
    public void loadFeedAsync() {
        Thread t = new Thread(this::loadFeed, "urlhaus-loader");
        t.setDaemon(true);
        t.start();
    }

    private void loadFeed() {

        log.info("[URLHAUS] Downloading CSV threat feed (background)...");

        int urlCount    = 0;
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

                    // 2️⃣ Domain extraction
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

            feedReady.set(true);
            log.info("[URLHAUS] Feed ready — {} malicious URLs, {} malicious domains", urlCount, domainCount);

        } catch (Exception e) {
            log.error("[URLHAUS] Failed to load feed: {}", e.getMessage());
        }
    }

    // ─────────────────────────────────────────────
    // Exact URL check
    // ─────────────────────────────────────────────
    public boolean isMalicious(String url) {
        if (!feedReady.get() || url == null || url.isBlank()) return false;
        return maliciousUrls.contains(url.trim());
    }

    // ─────────────────────────────────────────────
    // Domain-level check
    // ─────────────────────────────────────────────
    public boolean isMaliciousDomain(String url) {

        if (!feedReady.get() || url == null || url.isBlank()) return false;

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