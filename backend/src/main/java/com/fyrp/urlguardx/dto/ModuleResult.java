package com.fyrp.urlguardx.dto;

/**
 * Represents the output of a single analysis module.
 *
 * status values recognised by the React frontend:
 *   "Clean"   — module ran and found no issues
 *   "Warning" — module ran and found moderate risk signals
 *   "Danger"  — module ran and found definitive threat
 *   "Skipped" — Agentic Controller bypassed this module
 */
public class ModuleResult {

    private String status;   // Clean | Warning | Danger | Skipped
    private String details;  // Human-readable explanation shown in the dashboard card
    private double score;    // Raw module score 0-100 (not displayed, used by Risk Engine)

    public ModuleResult() {}

    public ModuleResult(String status, String details, double score) {
        this.status  = status;
        this.details = details;
        this.score   = score;
    }

    // Static factory helpers for readability inside services
    public static ModuleResult clean(String details, double score)   { return new ModuleResult("Clean",   details, score); }
    public static ModuleResult warning(String details, double score) { return new ModuleResult("Warning", details, score); }
    public static ModuleResult danger(String details, double score)  { return new ModuleResult("Danger",  details, score); }
    public static ModuleResult skipped(String reason)                { return new ModuleResult("Skipped", reason,  0.0);   }

    public String  getStatus()  { return status;  }
    public void    setStatus(String status) { this.status = status; }
    public String  getDetails() { return details; }
    public void    setDetails(String details) { this.details = details; }
    public double  getScore()   { return score;   }
    public void    setScore(double score) { this.score = score; }
}
