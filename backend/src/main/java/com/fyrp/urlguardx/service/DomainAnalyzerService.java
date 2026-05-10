package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;


@Service
public class DomainAnalyzerService {

    private static final Logger log = LoggerFactory.getLogger(DomainAnalyzerService.class);

    @Value("${whois.api.key:}")
    private String whoisApiKey;

    @Value("${whois.api.url:https://www.whoisxmlapi.com/whoisserver/WhoisService}")
    private String whoisApiUrl;

    private final WebClient webClient;

    // "Golden Domains" — major platforms with well-established age/trust
    private static final Set<String> GOLDEN_DOMAINS = Set.of(
            "google.com","microsoft.com","apple.com","amazon.com","facebook.com",
            "instagram.com","twitter.com","x.com","linkedin.com","github.com",
            "youtube.com","netflix.com","paypal.com","ebay.com","wikipedia.org",
            "mozilla.org","cloudflare.com","akamai.com","stackoverflow.com"
    );

    // High-risk registrars frequently seen in phishing campaigns
    private static final List<String> RISKY_REGISTRARS = List.of(
            "namecheap","namesilo","reg.ru","publicdomainregistry","epag","hosting.ua"
    );

    public DomainAnalyzerService(WebClient webClient) {
        this.webClient = webClient;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Main entry point
    // ─────────────────────────────────────────────────────────────────────
    public ModuleResult analyze(String rawUrl) {

        String host = extractHost(rawUrl);
        if (host == null) return ModuleResult.warning("Could not parse domain from URL.", 40.0);

        // Remove www.
        String domain = host.startsWith("www.") ? host.substring(4) : host;

        // Fast-path: Golden Domain
        if (GOLDEN_DOMAINS.stream().anyMatch(g -> domain.equalsIgnoreCase(g) || domain.endsWith("." + g))) {
            return ModuleResult.clean(
                    "Golden Domain: " + domain + " is a well-established, globally trusted domain with extensive age history.",
                    2.0);
        }
        log.info("[WHOIS] Using API Key: {}", whoisApiKey != null ? "CONFIGURED" : "MISSING");
        // If no API key is configured, fall back to heuristics only
        if (whoisApiKey == null || whoisApiKey.isBlank() || whoisApiKey.startsWith("YOUR_")) {
            return analyzeHeuristic(domain);
        }

        return analyzeViaWhois(domain);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  WHOIS API lookup
    // ─────────────────────────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    private ModuleResult analyzeViaWhois(String domain) {
        try {
            String uri = UriComponentsBuilder.fromHttpUrl(whoisApiUrl)
                    .queryParam("apiKey",       whoisApiKey)
                    .queryParam("domainName",   domain)
                    .queryParam("outputFormat", "JSON")
                    .toUriString();

            Map<String, Object> response = webClient.get()
                    .uri(uri)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(10))
                    .block();

            if (response == null) return analyzeHeuristic(domain);

            Map<String, Object> whoisRecord = (Map<String, Object>) response.get("WhoisRecord");
            if (whoisRecord == null)         return analyzeHeuristic(domain);

            String createdDate = (String) whoisRecord.get("createdDate");
            String registrar   = getNestedString(whoisRecord, "registrarName");
            String registrantCountry = getNestedString(whoisRecord, "registrantContact", "country");

            // ---- Age calculation ----
            long ageInDays = calculateAgeDays(createdDate);

            List<String> flags  = new ArrayList<>();
            double       score  = 0.0;

            if (ageInDays >= 0 && ageInDays < 30) {
                flags.add("Domain is only " + ageInDays + " days old — extremely new, high phishing risk.");
                score += 35;
            } else if (ageInDays >= 0 && ageInDays < 180) {
                flags.add("Domain is " + ageInDays + " days old (< 6 months) — recently registered.");
                score += 20;
            }

            if (registrar != null) {
                String lreg = registrar.toLowerCase();
                if (RISKY_REGISTRARS.stream().anyMatch(lreg::contains)) {
                    flags.add("Registrar '" + registrar + "' has elevated association with phishing domains.");
                    score += 15;
                }
            }

            if (registrantCountry != null && List.of("RU","CN","NG","PK","UA","KP").contains(registrantCountry)) {
                flags.add("Domain registered in jurisdiction: " + registrantCountry + " — elevated risk region.");
                score += 10;
            }

            // Privacy-proxy check (registrant name hidden)
            Object registrantContact = whoisRecord.get("registrantContact");
            if (registrantContact instanceof Map) {
                String org = getNestedString(whoisRecord, "registrantContact", "organization");
                if (org != null && (org.toLowerCase().contains("privacy") || org.toLowerCase().contains("whois guard"))) {
                    flags.add("Privacy proxy registration — registrant identity hidden.");
                    score += 8;
                }
            }

            score = Math.min(score, 100.0);
            String ageStr = ageInDays >= 0 ? ageInDays + " days" : "unknown";
            String regStr = registrar != null ? registrar : "Unknown";

            boolean unknownAge = ageInDays < 0;
            boolean unknownRegistrar = (registrar == null || registrar.isBlank());

            // 🚨 NEW RULE: Unknown WHOIS = Suspicious
            if (unknownAge || unknownRegistrar) {
                return ModuleResult.warning(
                        "Domain: " + domain + " | Age: " + ageStr + " | Registrar: " + regStr +
                                "WHOIS data incomplete — potential risk (new or obfuscated domain).",
                        25.0
                );
            }

            if (score >= 35) {
                return ModuleResult.danger(
                        "Domain: " + domain + " | Age: " + ageStr + " | Registrar: " + regStr +
                                ". Issues: " + String.join("; ", flags),
                        score
                );
            } else if (score >= 15) {
                return ModuleResult.warning(
                        "Domain: " + domain + " | Age: " + ageStr + " | Registrar: " + regStr +
                                ". Minor concerns: " + String.join("; ", flags),
                        score
                );
            } else {
                return ModuleResult.clean(
                        "Domain: " + domain + " | Age: " + ageStr + " | Registrar: " + regStr +
                                ". WHOIS data appears legitimate.",
                        score
                );
            }

        } catch (Exception e) {
            log.error("[DOMAIN] WHOIS API FAILED for {} → {}", domain, e.getMessage(), e);
            return analyzeHeuristic(domain);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Heuristic fallback (no API key)
    // ─────────────────────────────────────────────────────────────────────
    private ModuleResult analyzeHeuristic(String domain) {
        double score = 0.0;
        List<String> flags = new ArrayList<>();

        // TLD count (many dots = likely subdomain abuse)
        int dots = (int) domain.chars().filter(c -> c == '.').count();
        if (dots > 2) { flags.add("Complex subdomain structure (" + dots + " dots)."); score += 12; }

        // Domain length
        if (domain.length() > 30) { flags.add("Unusually long domain name (" + domain.length() + " chars)."); score += 8; }

        // Digit-heavy
        long digits = domain.chars().filter(Character::isDigit).count();
        if (digits > 3) { flags.add("Multiple digits in domain — obfuscation pattern."); score += 7; }

        if (flags.isEmpty()) {
            return ModuleResult.clean(
                    "WHOIS lookup unavailable — using heuristic analysis for: " + domain +
                            ". Possible API error, timeout, or rate limit.",
                    10.0
            );
        }
        return ModuleResult.warning(
                "WHOIS lookup failed (API error). Using heuristic fallback. Domain: " + domain,
                20.0
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────
    private String extractHost(String rawUrl) {
        try {
            if (!rawUrl.startsWith("http")) rawUrl = "http://" + rawUrl;
            return new URL(rawUrl).getHost();
        } catch (MalformedURLException e) { return null; }
    }

    private long calculateAgeDays(String dateStr) {
        if (dateStr == null) return -1;
        String[] formats = {
            "yyyy-MM-dd'T'HH:mm:ssXXX", "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd", "dd-MMM-yyyy"
        };
        for (String fmt : formats) {
            try {
                LocalDate created = LocalDate.parse(dateStr.substring(0, Math.min(dateStr.length(), 10)),
                                                    DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                return Duration.between(created.atStartOfDay(), LocalDate.now().atStartOfDay()).toDays();
            } catch (DateTimeParseException ignored) {}
        }
        return -1;
    }

    @SuppressWarnings("unchecked")
    private String getNestedString(Map<String, Object> map, String... keys) {
        Object current = map;
        for (int i = 0; i < keys.length - 1; i++) {
            if (!(current instanceof Map)) return null;
            current = ((Map<String, Object>) current).get(keys[i]);
        }
        if (!(current instanceof Map)) return null;
        Object val = ((Map<String, Object>) current).get(keys[keys.length - 1]);
        return val != null ? val.toString() : null;
    }

    private String getNestedString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val != null ? val.toString() : null;
    }

    public boolean isGoldenDomain(String url) {
        String host = extractHost(url);
        if (host == null) return false;
        String domain = host.startsWith("www.") ? host.substring(4) : host;
        return GOLDEN_DOMAINS.stream().anyMatch(g -> domain.equalsIgnoreCase(g) || domain.endsWith("." + g));
    }
}
