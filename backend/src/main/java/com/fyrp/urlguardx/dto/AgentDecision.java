package com.fyrp.urlguardx.dto;

import java.util.Set;

/**
 * Internal decision object produced by the Agentic Controller after
 * each analysis step.  Mirrors the LangGraph-style JSON decision:
 *
 *   { "nextStep": "risk_engine", "skip": ["ssl_validator", "domain_analyzer"] }
 *
 * Module identifiers used in the skip set:
 *   "lexical", "blacklist", "ssl", "domain"
 */
public class AgentDecision {

    public enum NextStep {
        RUN_BLACKLIST,
        RUN_DOMAIN,
        RUN_SSL,
        RISK_ENGINE,     // Jump straight to scoring
        TERMINATE_EARLY  // Definitive phish found — skip everything
    }

    private NextStep    nextStep;
    private Set<String> skip;
    private String      reason;  // Reasoning trace (logged for transparency)

    public AgentDecision(NextStep nextStep, Set<String> skip, String reason) {
        this.nextStep = nextStep;
        this.skip     = skip;
        this.reason   = reason;
    }

    public boolean shouldSkip(String module) {
        return skip != null && skip.contains(module);
    }

    public NextStep    getNextStep() { return nextStep; }
    public Set<String> getSkip()    { return skip;     }
    public String      getReason()  { return reason;   }
}
