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

        boolean upgraded    = false;
        String  resolvedUrl = rawUrl;

        if (!rawUrl.startsWith("https://")) {
            // HTTP — follow redirect chain to find HTTPS
            String httpsUrl = resolveHttpsUpgrade(rawUrl);
            if (httpsUrl != null) {
                log.info("[SSL] Upgraded {} → {}", rawUrl, httpsUrl);
                resolvedUrl = httpsUrl;
                rawUrl      = httpsUrl;
                upgraded    = true;
            } else {
                ModuleResult r = ModuleResult.danger(
                        "No TLS — URL uses plain HTTP. Data transmitted in cleartext; " +
                        "no certificate to inspect. Automatic risk penalty applied.", 70.0);
                r.setResolvedUrl(rawUrl);
                return r;
            }
        } else {
            // Already HTTPS — check for HTTPS→HTTP downgrade (server redirect back to HTTP)
            String firstHop = fetchLocation(rawUrl, "HEAD");
            if (firstHop == null) firstHop = fetchLocation(rawUrl, "GET");

            if (firstHop != null && firstHop.startsWith("http://")) {
                log.warn("[SSL] HTTPS→HTTP server downgrade: {} → {}", rawUrl, firstHop);
                ModuleResult r = ModuleResult.danger(
                        "HTTPS→HTTP downgrade: server redirects back to plain HTTP. " +
                        "Despite the https:// prefix, data is transmitted in cleartext. " +
                        "Redirect target: " + firstHop, 75.0);
                r.setResolvedUrl(firstHop);
                return r;
            }

            // Check for cross-domain HTTPS→HTTPS redirects (e.g. flipkart.in → flipkart.com)
            String resolved = resolveHttpsRedirect(rawUrl);
            if (resolved != null && !resolved.equalsIgnoreCase(rawUrl)) {
                log.info("[SSL] HTTPS cross-domain redirect: {} → {}", rawUrl, resolved);
                resolvedUrl = resolved;
                rawUrl      = resolved;
                upgraded    = true;
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

                SSLParameters sslParams = socket.getSSLParameters();
                sslParams.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(sslParams);

                socket.startHandshake();
            } catch (javax.net.ssl.SSLHandshakeException sslEx) {
                ModuleResult r = ModuleResult.danger(
                        "TLS handshake failed — certificate is untrusted, self-signed, or hostname mismatch. " +
                        "Detail: " + summarise(sslEx.getMessage()), 85.0);
                r.setResolvedUrl(resolvedUrl);
                return r;
            }

            // ---- Inspect certificate chain ----
            Certificate[]  chain = socket.getSession().getPeerCertificates();
            String         proto = socket.getSession().getProtocol();
            socket.close();

            if (chain == null || chain.length == 0) {
                ModuleResult r = ModuleResult.danger("Server presented an empty certificate chain.", 80.0);
                r.setResolvedUrl(resolvedUrl);
                return r;
            }

            X509Certificate leaf = (X509Certificate) chain[0];

            Date    notAfter  = leaf.getNotAfter();
            Date    now       = new Date();
            boolean expired   = now.after(notAfter);
            long    daysLeft  = (notAfter.getTime() - now.getTime()) / 86_400_000L;
            boolean selfSigned = leaf.getIssuerX500Principal().equals(leaf.getSubjectX500Principal());
            String  issuer    = leaf.getIssuerX500Principal().getName();
            boolean weakProto = proto.equals("TLSv1") || proto.equals("TLSv1.1") || proto.equals("SSLv3");

            // ---- HTTPS enforcement check ----
            // A valid cert alone doesn't mean HTTPS is the canonical protocol.
            // Sites like neverssl.com have a CDN cert but serve real content over HTTP.
            // If http://host → 200 (no HTTPS redirect), the site is HTTP-primary — flag it.
            boolean httpsEnforced = isHttpsEnforced(host);

            String prefix = upgraded ? "[Upgraded to HTTPS] " : "";

            ModuleResult r;
            if (expired) {
                r = ModuleResult.danger(
                        prefix + "Certificate EXPIRED. Issued by: " + shortName(issuer) +
                        ". Expired on: " + notAfter + ". This is a critical security failure.", 90.0);
            } else if (selfSigned) {
                r = ModuleResult.warning(
                        prefix + "Self-signed certificate detected. Issuer equals subject — not trusted by browsers. " +
                        "Expires: " + notAfter + ".", 55.0);
            } else if (!httpsEnforced) {
                r = ModuleResult.danger(
                        prefix + String.format(
                                "Certificate present (issued by %s) but HTTPS is NOT enforced — " +
                                "the HTTP version of this host is accessible without redirect to HTTPS. " +
                                "This site operates primarily over plain HTTP.",
                                shortName(issuer)), 72.0);
            } else if (daysLeft < 30) {
                r = ModuleResult.warning(
                        prefix + String.format("Certificate expiring soon (%d days left). Issuer: %s. Protocol: %s.",
                                daysLeft, shortName(issuer), proto), 35.0);
            } else if (weakProto) {
                r = ModuleResult.warning(
                        prefix + "Weak TLS protocol in use: " + proto + ". Upgrade to TLS 1.2+ recommended. " +
                        "Cert issued by: " + shortName(issuer) + ".", 30.0);
            } else {
                r = ModuleResult.clean(
                        prefix + String.format("Valid TLS certificate. Issued by: %s. Expires in %d days. Protocol: %s. HTTPS enforced.",
                                shortName(issuer), daysLeft, proto), 5.0);
            }
            r.setResolvedUrl(resolvedUrl);
            return r;

        } catch (Exception e) {
            log.warn("[SSL] Validation error for {}: {}", rawUrl, e.getMessage());
            ModuleResult r = ModuleResult.warning(
                    "SSL validation could not complete — host unreachable or connection timed out. " +
                    "Detail: " + summarise(e.getMessage()), 40.0);
            r.setResolvedUrl(resolvedUrl);
            return r;
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Returns true if http://host redirects to an HTTPS URL (HTTPS is enforced).
     * neverssl.com → http://neverssl.com returns 200 → false (not enforced) → Danger
     * google.com   → http://google.com   returns 301 → https://... → true (enforced) → Clean
     */
    private boolean isHttpsEnforced(String host) {
        String httpUrl = "http://" + host;
        try {
            String loc = fetchLocation(httpUrl, "HEAD");
            if (loc == null) loc = fetchLocation(httpUrl, "GET");
            boolean enforced = loc != null && loc.startsWith("https://");
            log.info("[SSL] HTTPS enforcement for {}: {}", host, enforced ? "YES" : "NO");
            return enforced;
        } catch (Exception e) {
            log.warn("[SSL] Enforcement check failed for {}: {}", host, e.getMessage());
            return true; // assume enforced on error — avoid false positives
        }
    }

    /**
     * For an already-HTTPS URL, follow HTTPS→HTTPS cross-domain redirects
     * (e.g. https://flipkart.in → https://www.flipkart.com).
     * Stops and returns null if a redirect to HTTP is encountered.
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

                if (location.startsWith("/")) {
                    URL base = new URL(current);
                    location = base.getProtocol() + "://" + base.getHost() + location;
                } else if (location.startsWith("//")) {
                    location = "https:" + location;
                }

                if (location.startsWith("https://")) {
                    current = location;
                } else {
                    break;
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
     * Returns the first HTTPS URL found in the chain, or null if none found.
     * Falls back from HEAD to GET for servers that block HEAD (e.g. Google).
     */
    private String resolveHttpsUpgrade(String rawUrl) {
        final int MAX_REDIRECTS = 8;
        String currentUrl = rawUrl;

        for (int hop = 0; hop < MAX_REDIRECTS; hop++) {
            String location = fetchLocation(currentUrl, "HEAD");
            if (location == null) location = fetchLocation(currentUrl, "GET");

            if (location == null) {
                log.info("[SSL] Chain ended at hop {} — no HTTPS upgrade", hop);
                return null;
            }

            log.info("[SSL] Redirect hop {}: {} → {}", hop, currentUrl, location);

            if (location.startsWith("https://")) {
                return location;
            }
            currentUrl = location;
        }

        log.warn("[SSL] Exceeded max redirect hops for {}", rawUrl);
        return null;
    }

    /**
     * Make a HEAD or GET request and return the Location header if it's a redirect (3xx),
     * or null otherwise (including on error or non-redirect responses).
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
