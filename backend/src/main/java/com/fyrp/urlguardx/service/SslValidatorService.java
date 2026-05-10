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
        // Only HTTPS URLs carry a certificate.
        if (!rawUrl.startsWith("https://")) {
            String httpsUrl = resolveHttpsUpgrade(rawUrl);
            if (httpsUrl != null) {
                log.info("[SSL] Upgraded {} to {}", rawUrl, httpsUrl);
                rawUrl = httpsUrl;
                upgraded = true;
            } else {
                return ModuleResult.danger(
                        "No TLS — URL uses plain HTTP. Data transmitted in cleartext; " +
                        "no certificate to inspect. Automatic risk penalty applied.", 70.0);
            }
        }

        try {
            URL    url  = new URL(rawUrl);
            String host = url.getHost();
            int    port = url.getPort() < 0 ? 443 : url.getPort();

            // ---- Open SSL handshake ----
            // Use SSLParameters with HTTPS endpoint identification so the JVM engine
            // validates the hostname (SNI + RFC 2818) *during* the handshake itself.
            // This is more reliable than the post-hoc HttpsURLConnection verifier,
            // which often returns false even for valid certs when used outside a real
            // HttpsURLConnection context.
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

    private String resolveHttpsUpgrade(String rawUrl) {
        String currentUrl = rawUrl;
        int redirects = 0;
        while (redirects < 3) {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(currentUrl).openConnection();
                conn.setInstanceFollowRedirects(false);
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                conn.setRequestMethod("HEAD");

                int status = conn.getResponseCode();
                if (status == HttpURLConnection.HTTP_MOVED_PERM ||
                    status == HttpURLConnection.HTTP_MOVED_TEMP ||
                    status == HttpURLConnection.HTTP_SEE_OTHER ||
                    status == 307 || status == 308) {
                    
                    String location = conn.getHeaderField("Location");
                    if (location != null) {
                        if (location.startsWith("https://")) {
                            return location;
                        } else if (location.startsWith("http://")) {
                            currentUrl = location;
                            redirects++;
                            continue;
                        } else if (location.startsWith("/")) {
                            // relative redirect
                            URL urlObj = new URL(currentUrl);
                            currentUrl = urlObj.getProtocol() + "://" + urlObj.getHost() + location;
                            redirects++;
                            continue;
                        }
                    }
                }
                break; // Not a redirect or no location header
            } catch (Exception e) {
                log.warn("[SSL] HTTP upgrade check failed for {}: {}", currentUrl, e.getMessage());
                break;
            }
        }
        return null;
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
