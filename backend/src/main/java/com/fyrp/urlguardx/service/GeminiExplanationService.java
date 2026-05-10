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
public class GeminiExplanationService {

    private static final Logger log = LoggerFactory.getLogger(GeminiExplanationService.class);

    @Value("${gemini.api.key:}")
    private String geminiApiKey;

    @Value("${gemini.api.url:https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent}")
    private String geminiApiUrl;

    private final WebClient webClient;

    public GeminiExplanationService(WebClient webClient) {
        this.webClient = webClient;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Main entry point
    // ─────────────────────────────────────────────────────────────────────
    public String generateExplanation(String url, int riskScore, String status,
                                      ModuleResult lexical, ModuleResult domain,
                                      ModuleResult ssl,     ModuleResult blacklist) {
        // 🚨 RULE-BASED OVERRIDE (HIGH RISK)
        if ("Danger".equals(blacklist.getStatus())) {
            return "This URL is confirmed malicious by threat intelligence (Google Safe Browsing / URLHaus). Avoid it immediately.";
        }

        if ("Danger".equals(domain.getStatus())) {
            return "The domain shows high-risk indicators such as very recent registration or suspicious WHOIS data, which are common in phishing attacks.";
        }

        if ("Warning".equals(ssl.getStatus())) {
            return "The connection is not secure or SSL validation failed, which exposes users to interception or phishing risks.";
        }

        if (geminiApiKey == null || geminiApiKey.isBlank() || geminiApiKey.startsWith("YOUR_")) {
            log.warn("[GEMINI] No API key configured — returning default explanation.");
            return buildFallbackExplanation(url, riskScore, status, lexical, domain, ssl, blacklist);
        }

        try {
            String prompt = buildPrompt(url, riskScore, status, lexical, domain, ssl, blacklist);
            String apiUrl = geminiApiUrl + "?key=" + geminiApiKey;

            Map<String, Object> requestBody = Map.of(
                    "contents", List.of(
                            Map.of("parts", List.of(Map.of("text", prompt)))
                    ),
                    "generationConfig", Map.of(
                            "temperature",     0.3,
                            "maxOutputTokens", 300,
                            "topP",            0.8
                    )
            );

            @SuppressWarnings("unchecked")
            Map<String, Object> response = webClient.post()
                    .uri(uriBuilder -> uriBuilder
                            .path(geminiApiUrl.replace("https://generativelanguage.googleapis.com", ""))
                            .queryParam("key", geminiApiKey)
                            .build())
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(15))
                    .block();

            String result = extractGeminiText(response);
            return result != null ? result :
                    buildFallbackExplanation(url, riskScore, status, lexical, domain, ssl, blacklist);
        } catch (Exception e) {
            log.error("[GEMINI] API call failed: {}", e.getMessage());
            return buildFallbackExplanation(url, riskScore, status, lexical, domain, ssl, blacklist);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Prompt engineering
    // ─────────────────────────────────────────────────────────────────────
    private String buildPrompt(String url, int riskScore, String status,
                               ModuleResult lexical, ModuleResult domain,
                               ModuleResult ssl, ModuleResult blacklist) {

        return """
You are a cybersecurity threat analyst.

Analyze the scan results and explain EXACTLY why this URL received its risk score.
Your explanation MUST reference specific signals from the modules below.

STRICT RULES:
- ML confidence should NEVER override blacklist or trusted domain evidence.
- Do NOT say "all checks passed" unless EVERY module is CLEAN
- If any module is WARNING or DANGER, you MUST mention it
- If domain is a known trusted brand and blacklist is clean,do NOT classify as dangerous even if lexical model shows warning.
- Prioritize explaining the MOST critical signals (Blacklist > Domain > SSL > Lexical)
- Be specific (e.g., "domain is newly registered", "no HTTPS", "ML detected phishing pattern")
- Write 2–3 sentences only
- No generic statements

URL: %s
Risk Score: %d/100
Final Status: %s

Module Results:
Lexical: [%s] %s
Domain: [%s] %s
SSL: [%s] %s
Threat Intel: [%s] %s

Now explain the REAL reason for the risk score.
""".formatted(
                url, riskScore, status,
                lexical.getStatus(), lexical.getDetails(),
                domain.getStatus(), domain.getDetails(),
                ssl.getStatus(), ssl.getDetails(),
                blacklist.getStatus(), blacklist.getDetails()
        );
    }
    // ─────────────────────────────────────────────────────────────────────
    //  Response extraction
    // ─────────────────────────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    private String extractGeminiText(Map<String, Object> response) {
        try {
            List<Map<String, Object>> candidates =
                    (List<Map<String, Object>>) response.get("candidates");

            if (candidates == null || candidates.isEmpty())
                return "AI response unavailable.";

            Map<String, Object> content =
                    (Map<String, Object>) candidates.get(0).get("content");

            List<Map<String, Object>> parts =
                    (List<Map<String, Object>>) content.get("parts");

            if (parts == null || parts.isEmpty())
                return "AI response incomplete.";

            return parts.get(0).get("text").toString();

        } catch (Exception e) {
            log.warn("[GEMINI] Failed to parse response: {}", e.getMessage());
            return "AI explanation could not be parsed.";
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Fallback — rule-based explanation when Gemini is unavailable
    // ─────────────────────────────────────────────────────────────────────
    private String buildFallbackExplanation(
            String url,
            int riskScore,
            String status,
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist) {

        // 1. Confirmed blacklist hit = highest severity
        if ("Danger".equalsIgnoreCase(blacklist.getStatus())) {
            return "This URL is confirmed malicious by threat intelligence sources such as Google Safe Browsing or URLHaus. It has been identified as phishing, malware, or an unsafe destination. Avoid visiting this link immediately.";
        }

        // 2. Golden trusted domain override
        if (domain.getDetails() != null &&
                domain.getDetails().toLowerCase().contains("golden domain")) {

            return "This URL belongs to a well-established trusted domain with strong domain age, valid registrar records, valid TLS security, and no blacklist detections. Minor lexical anomalies were safely overridden by trusted-domain validation.";
        }

        // 3. High lexical but safe threat intel
        if ("Danger".equalsIgnoreCase(lexical.getStatus())
                && "Clean".equalsIgnoreCase(blacklist.getStatus())
                && "Clean".equalsIgnoreCase(domain.getStatus())) {

            return "The machine learning engine detected unusual URL patterns, but no confirmed blacklist hits or domain abuse indicators were found. This often happens with legitimate domains containing uncommon URL structures. Overall risk remains low.";
        }

        // 4. WHOIS suspicious
        if ("Warning".equalsIgnoreCase(domain.getStatus())
                || "Danger".equalsIgnoreCase(domain.getStatus())) {

            return "The domain shows suspicious registration indicators such as recent creation, missing registrar details, or incomplete WHOIS information. These are common phishing characteristics and increase risk significantly.";
        }

        // 5. TLS issue
        if ("Warning".equalsIgnoreCase(ssl.getStatus())
                || "Danger".equalsIgnoreCase(ssl.getStatus())) {

            return "The TLS/SSL validation found security concerns such as missing HTTPS, invalid certificates, or weak trust signals. This increases phishing risk because secure communication cannot be fully verified.";
        }

        // 6. Final safe explanation
        return "This URL appears safe overall. Threat intelligence feeds found no confirmed phishing or malware reports, the domain is legitimate, and TLS security checks passed successfully. Risk remains low with no major indicators of abuse detected.";
    }
}
