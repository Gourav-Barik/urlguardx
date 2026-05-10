package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class SslValidatorService {

    private static final Logger log = LoggerFactory.getLogger(SslValidatorService.class);
    private static final int    TIMEOUT_MS = 6_000;

    // ─────────────────────────────────────────────────────────────────────
    //  Main entry point
    // ─────────────────────────────────────────────────────────────────────
    public ModuleResult validate(String rawUrl) {

        boolean upgraded = false;

        if (!rawUrl.startsWith("https://")) {
            // HTTP URL — try to follow redirect chain to HTTPS
            String httpsUrl = resolveHttpsUpgrade(rawUrl);
            if (httpsUrl != null) {
                log.info("[SSL] Upgraded {} → {}", rawUrl, httpsUrl);
                rawUrl   = httpsUrl;
                upgraded = true;
            } else {
                return ModuleResult.danger(
                        "No TLS — URL uses plain HTTP. Data transmitted in cleartext; " +
                        "no certificate to inspect. Automatic risk penalty applied.", 70.0);
            }
        } else {
            // Already HTTPS — but check if the server redirects cross-domain (e.g. flipkart.in → flipkart.com)
            // so we validate the cert of the *final* host, not the entry host.
            String resolved = resolveHttpsRedirect(rawUrl);
            if (resolved != null && !resolved.equalsIgnoreCase(rawUrl)) {
                log.info("[SSL] HTTPS cross-domain redirect: {} → {}", rawUrl, resolved);
                rawUrl   = resolved;
                upgraded = true;
            }
        }

        try {
            URL    url  = new URL(rawUrl);
            String host = url.getHost();
            int    port = url.getPort() < 0 ? 443 : url.getPort();

            // ---- Open SSL handshake ----
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket;
            try {
                java.net.Socket underlying = new java.net.Socket();
                underlying.connect(new java.net.InetSocketAddress(host, port), TIMEOUT_MS);
                socket = (SSLSocket) factory.createSocket(underlying, host, port, true);
                socket.setSoTimeout(TIMEOUT_MS);

                // Enable SNI and built-in hostname verification
                SSLParameters sslParams = socket.getSSLParameters();
                sslParams.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(sslParams);

                socket.startHandshake();  // throws SSLHandshakeException on hostname mismatch
            } catch (javax.net.ssl.SSLHandshakeException sslEx) {
                return ModuleResult.danger(
                        "TLS handshake failed — certificate is untrusted, self-signed, or hostname mismatch. " +
                        "Detail: " + summarise(sslEx.getMessage()), 85.0);
            }

            // ---- Inspect certificate chain ----
            Certificate[]  chain  = socket.getSession().getPeerCertificates();
            String         proto  = socket.getSession().getProtocol();
            socket.close();

            if (chain == null || chain.length == 0) {
                return ModuleResult.danger("Server presented an empty certificate chain.", 80.0);
            }

            X509Certificate leaf = (X509Certificate) chain[0];

            // Expiry check
            Date    notAfter  = leaf.getNotAfter();
            Date    now       = new Date();
            boolean expired   = now.after(notAfter);
            long    daysLeft  = (notAfter.getTime() - now.getTime()) / 86_400_000L;

            // Self-signed check (issuer == subject)
            boolean selfSigned = leaf.getIssuerX500Principal()
                                     .equals(leaf.getSubjectX500Principal());

            String issuer  = leaf.getIssuerX500Principal().getName();
            String subject = leaf.getSubjectX500Principal().getName();

            // ---- Protocol penalty ----
            boolean weakProto = proto.equals("TLSv1") || proto.equals("TLSv1.1") || proto.equals("SSLv3");

            // ---- Build result ----
            String prefix = upgraded ? "[Upgraded to HTTPS] " : "";

            if (expired) {
                return ModuleResult.danger(
                        prefix + "Certificate EXPIRED. Issued by: " + shortName(issuer) +
                        ". Expired on: " + notAfter + ". This is a critical security failure.", 90.0);
            }
            if (selfSigned) {
                return ModuleResult.warning(
                        prefix + "Self-signed certificate detected. Issuer equals subject — not trusted by browsers. " +
                        "Expires: " + notAfter + ".", 55.0);
            }
            if (daysLeft < 30) {
                return ModuleResult.warning(
                        prefix + String.format("Certificate expiring soon (%d days left). Issuer: %s. Protocol: %s.",
                                daysLeft, shortName(issuer), proto), 35.0);
            }
            if (weakProto) {
                return ModuleResult.warning(
                        prefix + "Weak TLS protocol in use: " + proto + ". Upgrade to TLS 1.2+ recommended. " +
                        "Cert issued by: " + shortName(issuer) + ".", 30.0);
            }

            return ModuleResult.clean(
                    prefix + String.format("Valid TLS certificate. Issued by: %s. Expires in %d days. Protocol: %s.",
                            shortName(issuer), daysLeft, proto), 5.0);

        } catch (Exception e) {
            log.warn("[SSL] Validation error for {}: {}", rawUrl, e.getMessage());
            return ModuleResult.warning(
                    "SSL validation could not complete — host unreachable or connection timed out. " +
                    "This is suspicious for an HTTPS URL: " + summarise(e.getMessage()), 40.0);
        }
    }


    // ─────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────

    /**
     * For an already-HTTPS URL, follow any cross-domain HTTPS→HTTPS redirects
     * (e.g. https://flipkart.in → https://www.flipkart.com) so the SSL check
     * validates the certificate of the *final* host, not the entry host.
     * Returns null if there is no redirect or if the chain stays on the same host.
     */
    private String resolveHttpsRedirect(String httpsUrl) {
        final int MAX_HOPS = 5;
        String current = httpsUrl;
        for (int hop = 0; hop < MAX_HOPS; hop++) {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(current).openConnection();
                conn.setInstanceFollowRedirects(false);
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                conn.setRequestMethod("HEAD");
                conn.setRequestProperty("User-Agent",
                        "Mozilla/5.0 (compatible; URLGuardX-SecurityScanner/1.0)");

                int status = conn.getResponseCode();
                boolean isRedirect = (status == 301 || status == 302 ||
                                      status == 303 || status == 307 || status == 308);
                if (!isRedirect) break;

                String location = conn.getHeaderField("Location");
                if (location == null || location.isBlank()) break;

                // Resolve relative locations
                if (location.startsWith("/")) {
                    URL base = new URL(current);
                    location = base.getProtocol() + "://" + base.getHost() + location;
                } else if (location.startsWith("//")) {
                    location = "https:" + location;
                }

                if (location.startsWith("https://")) {
                    current = location;
                } else {
                    break; // Redirect to HTTP — stop (handled by resolveHttpsUpgrade)
                }
            } catch (Exception e) {
                log.warn("[SSL] HTTPS redirect follow failed at hop {}: {}", hop, e.getMessage());
                break;
            }
        }
        return current.equalsIgnoreCase(httpsUrl) ? null : current;
    }

    /**
     * Follow the redirect chain for an HTTP URL.
     * Returns the first HTTPS URL found in the chain, or null if the chain
     * never reaches HTTPS (or exceeds MAX_REDIRECTS without finding it).
     *
     * Handles multi-hop chains such as:
     *   http://google.com → http://www.google.com → https://www.google.com  ✅
     *
     * Falls back from HEAD to GET if the server returns an unexpected status
     * (some servers, including Google, block HEAD from non-browser clients).
     */
    private String resolveHttpsUpgrade(String rawUrl) {
        final int MAX_REDIRECTS = 8;
        String currentUrl = rawUrl;

        for (int hop = 0; hop < MAX_REDIRECTS; hop++) {
            String location = fetchLocation(currentUrl, "HEAD");

            // HEAD might be blocked (e.g. Google returns 405) — retry with GET
            if (location == null) {
                location = fetchLocation(currentUrl, "GET");
            }

            if (location == null) {
                log.info("[SSL] Chain ended at hop {} with no redirect location — no HTTPS upgrade", hop);
                return null;
            }

            log.info("[SSL] Redirect hop {}: {} → {}", hop, currentUrl, location);

            if (location.startsWith("https://")) {
                return location; // ✅ Found HTTPS
            }
            currentUrl = location; // Still HTTP, keep following
        }

        log.warn("[SSL] Exceeded {} redirect hops without reaching HTTPS for {}", MAX_REDIRECTS, rawUrl);
        return null;
    }

    /**
     * Make a HEAD or GET request and return the Location header if the response
     * is a redirect (3xx), or null otherwise (including on error or non-redirect).
     */
    private String fetchLocation(String url, String method) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod(method);
            conn.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36");

            int status = conn.getResponseCode();
            log.debug("[SSL] {} {} → {}", method, url, status);

            boolean isRedirect = (status == 301 || status == 302 ||
                                  status == 303 || status == 307 || status == 308);
            if (!isRedirect) return null;

            String location = conn.getHeaderField("Location");
            if (location == null || location.isBlank()) return null;

            // Resolve relative and scheme-relative URLs
            if (location.startsWith("//")) {
                return "https:" + location;
            } else if (location.startsWith("/")) {
                URL base = new URL(url);
                return base.getProtocol() + "://" + base.getHost()
                        + (base.getPort() != -1 ? ":" + base.getPort() : "")
                        + location;
            } else if (!location.startsWith("http")) {
                URL base = new URL(url);
                return base.getProtocol() + "://" + base.getHost() + "/" + location;
            }
            return location;
        } catch (Exception e) {
            log.warn("[SSL] {} request failed for {}: {}", method, url, e.getMessage());
            return null;
        }
    }


    private String shortName(String dn) {
        if (dn == null) return "Unknown";
        // Extract CN or O from the X500 distinguished name
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("O=") && !part.trim().startsWith("OU=")) {
                return part.trim().substring(2);
            }
        }
        return dn.length() > 60 ? dn.substring(0, 60) + "…" : dn;
    }

    private String summarise(String msg) {
        if (msg == null) return "Unknown error";
        return msg.length() > 120 ? msg.substring(0, 120) + "…" : msg;
    }
}
