package com.fyrp.urlguardx.dto;

/**
 * Top-level API response consumed by the React frontend.
 *
 * Contract (must match App.jsx exactly):
 * {
 *   "riskScore"  : 78,
 *   "status"     : "HIGH RISK",
 *   "explanation": "Gemini reasoning text...",
 *   "modules": {
 *     "lexical"  : { "status": "Danger",  "details": "..." },
 *     "domain"   : { "status": "Skipped", "details": "..." },
 *     "ssl"      : { "status": "Clean",   "details": "..." },
 *     "blacklist": { "status": "Danger",  "details": "..." }
 *   }
 * }
 */
public class ScanResponse {

    private int           riskScore;    // 0-100
    private String        status;       // SAFE | SUSPICIOUS | HIGH RISK
    private String        explanation;  // Gemini AI synthesis

    private ModulesWrapper modules;

    public ScanResponse() {}

    // ---- Inner wrapper so JSON key is "modules" ----
    public static class ModulesWrapper {
        private ModuleResult lexical;
        private ModuleResult domain;
        private ModuleResult ssl;
        private ModuleResult blacklist;

        public ModulesWrapper(ModuleResult lexical, ModuleResult domain,
                              ModuleResult ssl,     ModuleResult blacklist) {
            this.lexical   = lexical;
            this.domain    = domain;
            this.ssl       = ssl;
            this.blacklist = blacklist;
        }

        public ModuleResult getLexical()   { return lexical;   }
        public ModuleResult getDomain()    { return domain;    }
        public ModuleResult getSsl()       { return ssl;       }
        public ModuleResult getBlacklist() { return blacklist; }
    }

    // ---- Derive status label from riskScore ----
    public static String deriveStatus(int score) {
        if (score >= 70) return "HIGH RISK";
        if (score >= 40) return "SUSPICIOUS";
        return "SAFE";
    }

    // ---- Getters & Setters ----
    public int            getRiskScore()   { return riskScore;   }
    public void           setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public String         getStatus()      { return status;      }
    public void           setStatus(String status) { this.status = status; }
    public String         getExplanation() { return explanation; }
    public void           setExplanation(String explanation) { this.explanation = explanation; }
    public ModulesWrapper getModules()     { return modules;     }
    public void           setModules(ModulesWrapper modules) { this.modules = modules; }
}
