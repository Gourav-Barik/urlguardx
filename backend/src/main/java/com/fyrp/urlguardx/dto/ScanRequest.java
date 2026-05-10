package com.fyrp.urlguardx.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Incoming scan request body: {"url": "https://..."}
 */
public class ScanRequest {

    @NotBlank(message = "URL must not be blank")
    private String url;

    public ScanRequest() {}

    public ScanRequest(String url) {
        this.url = url;
    }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
}
