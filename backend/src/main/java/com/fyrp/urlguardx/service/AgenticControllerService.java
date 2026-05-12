package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import com.fyrp.urlguardx.dto.ScanResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;

@Service
public class AgenticControllerService {

    private static final Logger log =
            LoggerFactory.getLogger(AgenticControllerService.class);

    private final LexicalAnalysisService lexicalService;
    private final BlacklistCheckerService blacklistService;
    private final SslValidatorService sslService;
    private final DomainAnalyzerService domainService;
    private final RiskScoringEngine riskEngine;
    private final GeminiExplanationService geminiService;

    public AgenticControllerService(
            LexicalAnalysisService lexicalService,
            BlacklistCheckerService blacklistService,
            SslValidatorService sslService,
            DomainAnalyzerService domainService,
            RiskScoringEngine riskEngine,
            GeminiExplanationService geminiService
    ) {
        this.lexicalService = lexicalService;
        this.blacklistService = blacklistService;
        this.sslService = sslService;
        this.domainService = domainService;
        this.riskEngine = riskEngine;
        this.geminiService = geminiService;
    }

    public ScanResponse orchestrate(String rawUrl) {

        String url = normalizeUrl(rawUrl);

        log.info("[AGENT] Starting scan for {}", url);

        /*
         STAGE 1 — CONCURRENT LEXICAL & BLACKLIST
         Normalize scheme to http:// before ML analysis so https://neverssl.com
         and http://neverssl.com produce identical model inputs and cache keys.
        */
        String lexicalUrl = url.replaceFirst("^https://", "http://");
        
        CompletableFuture<ModuleResult> lexicalFuture = CompletableFuture.supplyAsync(() -> {
            try { return lexicalService.analyze(lexicalUrl); } 
            catch (Exception e) { return ModuleResult.warning("ML analysis failed: " + e.getMessage(), 50.0); }
        });
        
        CompletableFuture<ModuleResult> blacklistFuture = CompletableFuture.supplyAsync(() -> {
            try { return blacklistService.check(url); } 
            catch (Exception e) { return ModuleResult.warning("Threat check failed", 50.0); }
        });

        ModuleResult blacklist;
        try { blacklist = blacklistFuture.join(); } 
        catch (Exception e) { blacklist = ModuleResult.warning("Threat intel offline", 50.0); }

        if ("Danger".equalsIgnoreCase(blacklist.getStatus())) {
            ModuleResult lexical;
            try { lexical = lexicalFuture.join(); } 
            catch (Exception e) { lexical = ModuleResult.warning("ML skipped/failed", 50.0); }

            ModuleResult ssl = ModuleResult.skipped("Skipped after confirmed blacklist hit");
            ModuleResult domain = ModuleResult.skipped("Skipped after confirmed blacklist hit");

            return buildResponse(url, lexical, domain, ssl, blacklist);
        }

        boolean goldenDomain = false;
        try { goldenDomain = domainService.isGoldenDomain(url); } catch (Exception ignored) {}

        CompletableFuture<ModuleResult> domainFuture = goldenDomain 
                ? CompletableFuture.completedFuture(ModuleResult.clean("Golden domain detected — WHOIS skipped", 2.0))
                : CompletableFuture.supplyAsync(() -> {
                    try { return domainService.analyze(url); } 
                    catch (Exception e) { return ModuleResult.warning("Domain analysis failed", 50.0); }
                });

        CompletableFuture<ModuleResult> sslFuture = CompletableFuture.supplyAsync(() -> {
            try { return sslService.validate(url); } 
            catch (Exception e) { return ModuleResult.warning("SSL validation failed", 50.0); }
        });

        ModuleResult lexical;
        try { lexical = lexicalFuture.join(); } 
        catch (Exception e) { lexical = ModuleResult.warning("ML analysis failed", 50.0); }

        ModuleResult domain;
        try { domain = domainFuture.join(); } 
        catch (Exception e) { domain = ModuleResult.warning("Domain analysis failed", 50.0); }

        ModuleResult ssl;
        try { ssl = sslFuture.join(); } 
        catch (Exception e) { ssl = ModuleResult.warning("SSL validation failed", 50.0); }

        try {
            return buildResponse(url, lexical, domain, ssl, blacklist);
        } catch (Exception e) {
            log.error("Failed to build response", e);
            throw new RuntimeException("Orchestration failed safely", e);
        }
    }

    private ScanResponse buildResponse(
            String url,
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist
    ) {

        int score = riskEngine.calculate(
                lexical,
                domain,
                ssl,
                blacklist
        );

        String status = riskEngine.getFinalStatus(score);

        String explanation =
                geminiService.generateExplanation(
                        url,
                        score,
                        status,
                        lexical,
                        domain,
                        ssl,
                        blacklist
                );

        ScanResponse response = new ScanResponse();
        // resolvedUrl = the true final URL (after HTTPS upgrade, cross-domain redirect,
        // or HTTP downgrade detection). This is what the Analyzed Vector should display.
        String resolvedUrl = ssl.getResolvedUrl();
        String finalUrl    = resolvedUrl != null ? normalizeUrl(resolvedUrl) : url;
        response.setCanonicalUrl(url);     // original input (for reference)
        response.setResolvedUrl(finalUrl); // final effective URL shown in UI
        response.setRiskScore(score);
        response.setStatus(status);
        response.setExplanation(explanation);
        response.setModules(
                new ScanResponse.ModulesWrapper(
                        lexical,
                        domain,
                        ssl,
                        blacklist
                )
        );

        return response;
    }

    /**
     * Canonicalize the URL before it reaches any service or cache:
     *  - Prepend https:// if no scheme is present
     *  - Lowercase the host
     *  - Strip trailing slash from the path (so /neverssl.com == /neverssl.com/)
     *  - Remove default ports (80 for http, 443 for https)
     *
     * This means http://neverssl.com and http://neverssl.com/ are treated
     * as the same URL throughout the entire analysis pipeline.
     */
    private String normalizeUrl(String raw) {
        raw = raw.trim();
        if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
            // Bare IPs default to http:// so the SSL module follows the redirect chain.
            // Bare domains default to https://.
            String hostPart = raw.split("/")[0].split(":")[0];
            boolean isBareIp = hostPart.matches("(\\d{1,3}\\.){3}\\d{1,3}");
            raw = (isBareIp ? "http://" : "https://") + raw;
        }
        try {
            java.net.URL parsed = new java.net.URL(raw);
            String scheme   = parsed.getProtocol().toLowerCase();
            String host     = parsed.getHost().toLowerCase();
            int    port     = parsed.getPort();
            String path     = parsed.getPath();
            String query    = parsed.getQuery();
            String fragment = parsed.getRef();

            // Strip default ports
            if ((scheme.equals("http")  && port == 80)  ||
                (scheme.equals("https") && port == 443)) {
                port = -1;
            }

            // Strip ALL trailing slashes from the path
            // e.g. http://neverssl.com/  → path="/"  → becomes ""
            //      http://example.com/a/ → path="/a/" → becomes "/a"
            while (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }

            StringBuilder sb = new StringBuilder(scheme).append("://").append(host);
            if (port != -1) sb.append(":").append(port);
            sb.append(path);
            // Drop query string and fragment — they are not part of the canonical security identity
            // e.g. https://www.google.com/?gws_rd=ssl → https://www.google.com

            return sb.toString();
        } catch (Exception e) {
            log.warn("[AGENT] URL normalization failed for '{}': {}", raw, e.getMessage());
            return raw;
        }
    }

}