package com.fyrp.urlguardx.service;

import com.fyrp.urlguardx.dto.ModuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Service
public class SslValidatorService {

    private static final Logger log = LoggerFactory.getLogger(SslValidatorService.class);
    private static final int    TIMEOUT_MS = 3_000; // 3s per request — reduces worst-case chain from 36s to ~12s

    // ─────────────────────────────────────────────────────────────────────
    //  Main entry point
    // ─────────────────────────────────────────────────────────────────────
    public ModuleResult validate(String rawUrl) {

        boolean upgraded    = false;
        String  resolvedUrl = rawUrl;

        if (!rawUrl.startsWith("https://")) {
            String ipHost;
            try { ipHost = new URL(rawUrl).getHost(); } catch (Exception e) { ipHost = ""; }
            boolean isIpHost = ipHost.matches("(\\d{1,3}\\.){3}\\d{1,3}");

            // Step 1: Follow HTTP redirect chain
            String httpsUrl = resolveHttpsUpgrade(rawUrl);

            if (httpsUrl != null) {
                log.info("[SSL] Upgraded {} → {}", rawUrl, httpsUrl);
                rawUrl  = httpsUrl;
                upgraded = true;
                // Step 2a: If redirect landed on https://IP (e.g. https://1.1.1.1),
                // read the cert SAN to get the real domain (one.one.one.one).
                String upgradedHost;
                try { upgradedHost = new URL(rawUrl).getHost(); } catch (Exception e) { upgradedHost = ""; }
                if (upgradedHost.matches("(\\d{1,3}\\.){3}\\d{1,3}")) {
                    String certDomain = readCertDomainForIp(upgradedHost);
                    if (certDomain != null) { rawUrl = "https://" + certDomain; }
                }
            } else if (isIpHost) {
                // Step 2b: Port 80 didn't redirect — connect to https://IP:443 directly.
                String certDomain = readCertDomainForIp(ipHost);
                if (certDomain != null) {
                    log.info("[SSL] IP {} cert domain: {}", ipHost, certDomain);
                    rawUrl  = "https://" + certDomain;
                    upgraded = true;
                } else {
                    ModuleResult r = ModuleResult.danger(
                            "No TLS — IP address does not serve HTTPS or connection refused.", 70.0);
                    r.setResolvedUrl(rawUrl);
                    return r;
                }
            } else {
                ModuleResult r = ModuleResult.danger(
                        "No TLS — URL uses plain HTTP. Data transmitted in cleartext; " +
                        "no certificate to inspect. Automatic risk penalty applied.", 70.0);
                r.setResolvedUrl(rawUrl);
                return r;
            }

            // Step 3: Follow one HTTPS→HTTPS cross-domain hop on the resolved domain
            // (e.g. https://dns.google → https://dns.google.com, or https://one.one.one.one stays)
            // Strip path — we only want scheme+host (avoids https://one.one.one.one/dns artifacts)
            String crossHop = fetchLocation(rawUrl, "HEAD");
            if (crossHop == null) crossHop = fetchLocation(rawUrl, "GET");
            if (crossHop != null && crossHop.startsWith("https://")) {
                try {
                    String crossHost = new URL(crossHop).getHost();
                    String crossOrigin = "https://" + crossHost;
                    if (!crossHost.isEmpty() && !crossOrigin.equalsIgnoreCase(rawUrl)) {
                        log.info("[SSL] IP resolved HTTPS cross-domain: {} → {}", rawUrl, crossOrigin);
                        rawUrl = crossOrigin;
                    }
                } catch (Exception ignored) {}
            }

            resolvedUrl = rawUrl;
        } else {
            // Already HTTPS — one HEAD+GET pair handles BOTH downgrade and cross-domain detection.
            // This replaces the old: downgrade-HEAD, downgrade-GET, resolveHttpsRedirect-HEAD (3 calls).
            String firstHop = fetchLocation(rawUrl, "HEAD");
            if (firstHop == null) firstHop = fetchLocation(rawUrl, "GET");

            if (firstHop != null && firstHop.startsWith("http://")) {
                // HTTPS→HTTP downgrade
                log.warn("[SSL] HTTPS→HTTP downgrade: {} → {}", rawUrl, firstHop);
                ModuleResult r = ModuleResult.danger(
                        "HTTPS→HTTP downgrade: server redirects back to plain HTTP. " +
                        "Despite the https:// prefix, data is transmitted in cleartext. " +
                        "Redirect target: " + firstHop, 75.0);
                r.setResolvedUrl(firstHop);
                return r;
            }

            if (firstHop != null && firstHop.startsWith("https://") && !firstHop.equalsIgnoreCase(rawUrl)) {
                // HTTPS→HTTPS cross-domain redirect (e.g. flipkart.in → flipkart.com)
                log.info("[SSL] HTTPS cross-domain redirect: {} → {}", rawUrl, firstHop);
                resolvedUrl = firstHop;
                rawUrl      = firstHop;
                upgraded    = true;
            }
            // firstHop == null means 200 response (Cloudflare CDN, etc.) — proceed to cert check
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

            // If HTTPS is not enforced, the effective URL is the HTTP version
            if (!httpsEnforced) {
                resolvedUrl = "http://" + host;
            }

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
     * Returns true if http://host redirects to HTTPS (HTTPS is enforced).
     *
     * Three outcomes:
     *   - 3xx → https://...  : enforced = true   (google.com, one.one.one.one)
     *   - 2xx / 3xx → http:/ : enforced = false  (neverssl.com, eu.httpbin.org)
     *   - Exception (DNS fail, timeout): enforced = true  (exotic TLDs like .google — avoid false DANGER)
     */
    private boolean isHttpsEnforced(String host) {
        if (host.matches("(\\d{1,3}\\.){3}\\d{1,3}")) return true; // IPs handled via cert-domain path
        String currentUrl = "http://" + host;
        try {
            for (int i = 0; i < 5; i++) {
                String loc = fetchLocationWithThrow(currentUrl, "HEAD");
                if (loc == null) {
                    loc = fetchLocationWithThrow(currentUrl, "GET");
                }
                
                if (loc == null) {
                    // No redirect. Ended on HTTP.
                    log.info("[SSL] HTTPS enforcement for {}: NO (ended at {})", host, currentUrl);
                    return false;
                }
                
                if (loc.startsWith("https://")) {
                    log.info("[SSL] HTTPS enforcement for {}: YES", host);
                    return true;
                }
                currentUrl = loc;
            }
            return false;
        } catch (Exception e) {
            log.warn("[SSL] Enforcement check unreachable for {} — assuming enforced: {}", host, e.getMessage());
            return true;
        }
    }

    /**
     * Connect to an IPv4 address on port 443 with hostname verification DISABLED,
     * read the TLS certificate, and return the first non-wildcard DNS SAN.
     * Used as fallback when http://IP redirect detection fails (e.g. port 80 blocked).
     */
    private String readCertDomainForIp(String ipHost) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{ new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            SSLSocketFactory factory = ctx.getSocketFactory();

            java.net.Socket underlying = new java.net.Socket();
            underlying.connect(new java.net.InetSocketAddress(ipHost, 443), TIMEOUT_MS);
            SSLSocket socket = (SSLSocket) factory.createSocket(underlying, ipHost, 443, true);
            socket.setSoTimeout(TIMEOUT_MS);
            // No endpoint identification algorithm — intentionally skip hostname check for IPs
            socket.startHandshake();

            Certificate[] chain = socket.getSession().getPeerCertificates();
            socket.close();

            if (chain == null || chain.length == 0) return null;
            return extractDomainFromCert((X509Certificate) chain[0]);
        } catch (Exception e) {
            log.warn("[SSL] IP cert read failed for {}:443 — {}", ipHost, e.getMessage());
            return null;
        }
    }

    /**
     * Extract the best hostname from a cert's Subject Alternative Names (SAN).
     * Returns the first non-wildcard DNS SAN; falls back to CN from subject DN.
     */
    private String extractDomainFromCert(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                String wildcard = null;
                for (List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                        String dns = String.valueOf(san.get(1));
                        if (!dns.startsWith("*")) return dns;
                        if (wildcard == null) wildcard = dns.substring(2); // strip *.
                    }
                }
                if (wildcard != null) return wildcard;
            }
        } catch (CertificateParsingException e) {
            log.warn("[SSL] SAN parse error: {}", e.getMessage());
        }
        for (String part : cert.getSubjectX500Principal().getName().split(",")) {
            String t = part.trim();
            if (t.startsWith("CN=")) return t.substring(3);
        }
        return null;
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
            return fetchLocationWithThrow(url, method);
        } catch (Exception e) {
            log.warn("[SSL] {} request failed for {}: {}", method, url, e.getMessage());
            return null;
        }
    }

    private String fetchLocationWithThrow(String url, String method) throws Exception {
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
