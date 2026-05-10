package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import com.fyrp.urlguardx.dto.ScanResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

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
         STEP 1 — LEXICAL ALWAYS RUNS
         */
        ModuleResult lexical = lexicalService.analyze(url);

        /*
         STEP 2 — BLACKLIST ALWAYS RUNS
         (even if ML says danger)
         */
        ModuleResult blacklist = blacklistService.check(url);

        /*
         FAIL FAST ONLY FOR REAL BLACKLIST HIT
         */
        if ("Danger".equalsIgnoreCase(blacklist.getStatus())) {

            ModuleResult ssl = ModuleResult.skipped(
                    "Skipped after confirmed blacklist hit");

            ModuleResult domain = ModuleResult.skipped(
                    "Skipped after confirmed blacklist hit");

            return buildResponse(
                    url,
                    lexical,
                    domain,
                    ssl,
                    blacklist
            );
        }

        /*
         STEP 3 — TRUSTED DOMAIN CHECK
         */
        boolean goldenDomain = domainService.isGoldenDomain(url);

        ModuleResult domain;
        ModuleResult ssl;

        /*
         Golden domain:
         Skip WHOIS only
         Still run SSL
         */
        if (goldenDomain) {
            domain = ModuleResult.clean(
                    "Golden domain detected — WHOIS skipped",
                    2.0
            );

            ssl = sslService.validate(url);
        }


        /*
         Standard Full Scan
         */
        else {
            domain = domainService.analyze(url);
            ssl = sslService.validate(url);
        }

        return buildResponse(
                url,
                lexical,
                domain,
                ssl,
                blacklist
        );
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
            raw = "https://" + raw;
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

            // Strip trailing slash from path (treat /neverssl.com == /neverssl.com/)
            if (path.endsWith("/") && path.length() > 1) {
                path = path.substring(0, path.length() - 1);
            }

            StringBuilder sb = new StringBuilder(scheme).append("://").append(host);
            if (port != -1) sb.append(":").append(port);
            sb.append(path);
            if (query    != null) sb.append("?").append(query);
            if (fragment != null) sb.append("#").append(fragment);

            return sb.toString();
        } catch (Exception e) {
            log.warn("[AGENT] URL normalization failed for '{}': {}", raw, e.getMessage());
            return raw; // fall back to original
        }
    }

}