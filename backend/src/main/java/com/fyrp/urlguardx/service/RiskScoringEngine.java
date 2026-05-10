package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.springframework.stereotype.Service;

@Service
public class RiskScoringEngine {

    public int calculate(
            ModuleResult lexical,
            ModuleResult domain,
            ModuleResult ssl,
            ModuleResult blacklist
    ) {

        /*
         RULE 1:
         Blacklist danger = immediate high risk
         */
        if ("Danger".equalsIgnoreCase(
                blacklist.getStatus())) {
            return 95;
        }

        int dangerCount = 0;
        int warningCount = 0;

        if ("Danger".equalsIgnoreCase(lexical.getStatus())) dangerCount++;
        if ("Danger".equalsIgnoreCase(domain.getStatus())) dangerCount++;
        if ("Danger".equalsIgnoreCase(ssl.getStatus())) dangerCount++;

        if ("Warning".equalsIgnoreCase(lexical.getStatus())) warningCount++;
        if ("Warning".equalsIgnoreCase(domain.getStatus())) warningCount++;
        if ("Warning".equalsIgnoreCase(ssl.getStatus())) warningCount++;


        if (dangerCount >= 2) {
            return 85;
        }


        if (
                "Danger".equalsIgnoreCase(lexical.getStatus())
                        && "Clean".equalsIgnoreCase(blacklist.getStatus())
                        && "Clean".equalsIgnoreCase(domain.getStatus())
        ) {
            // ML-only danger should not dominate
            return 35;
        }

        if (dangerCount == 1 && warningCount >= 1) {
            return 60;
        }

        /*
         RULE 4:
         Reduce ML false positives
         */
        double lexicalScore = lexical.getScore();

        if (lexicalScore > 85
                && "Clean".equalsIgnoreCase(blacklist.getStatus())
                && "Clean".equalsIgnoreCase(domain.getStatus())) {
            lexicalScore *= 0.35;
        }

        /*
         Final weighted score
         */

        double finalScore =
                (blacklist.getScore() * 0.40) +
                        (domain.getScore() * 0.25) +
                        (ssl.getScore() * 0.20) +
                        (lexicalScore * 0.15);

        return Math.min(
                (int)Math.round(finalScore),
                100
        );
    }

    public String getFinalStatus(int score) {

        if (score >= 75) {
            return "High Risk";
        }

        if (score >= 40) {
            return "Suspicious";
        }

        return "Safe";
    }
}