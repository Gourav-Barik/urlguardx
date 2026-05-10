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

    private String normalizeUrl(String url) {
        url = url.trim();

        if (!url.startsWith("http://")
                && !url.startsWith("https://")) {
            return "https://" + url;
        }

        return url;
    }
}