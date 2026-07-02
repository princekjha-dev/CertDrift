package com.certdrift.scoring;

import com.certdrift.model.Finding;
import com.certdrift.model.Findings;
import com.certdrift.model.Snapshot;
import com.certdrift.model.TlsSnapshot;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DefaultRiskScoringEngine implements RiskScoringEngine {

    @Override
    public Snapshot score(Snapshot snapshot) {
        Findings findings = new Findings();
        TlsSnapshot tls = snapshot.tls();

        if (tls != null) {
            if (tls.daysRemaining() <= 0) {
                findings = findings.with(new Finding("expired-certificate", "Critical", "Expired certificate", "The certificate is expired.", "Renew the certificate immediately."));
            } else if (tls.daysRemaining() <= 30) {
                findings = findings.with(new Finding("expiring-soon", "Medium", "Certificate expiring soon", "The certificate expires soon.", "Renew the certificate before it expires."));
            }

            if (tls.negotiatedProtocol() != null && isWeakProtocol(tls.negotiatedProtocol())) {
                findings = findings.with(new Finding("weak-protocol", "Critical", "Deprecated TLS protocol", "The negotiated TLS protocol is deprecated.", "Disable legacy TLS versions and prefer TLS 1.2+."));
            }

            if (tls.selfSigned()) {
                findings = findings.with(new Finding("self-signed", "High", "Self-signed certificate", "The certificate is self-signed.", "Replace it with a certificate issued by a trusted CA."));
            }

            if (isWeakCipher(tls.negotiatedCipherSuite())) {
                findings = findings.with(new Finding("weak-cipher", "High", "Weak or deprecated cipher", "The negotiated cipher suite is weak or deprecated.", "Disable weak ciphers and prefer modern AEAD suites."));
            }
        }

        if (snapshot.headers() != null) {
            var headers = snapshot.headers();
            if (!headers.presenceFlags().containsKey("Strict-Transport-Security") && snapshot.metadata() != null) {
                findings = findings.with(new Finding("missing-hsts", "Critical", "Missing HSTS", "HSTS is not present on the HTTPS host.", "Add a Strict-Transport-Security header with a long max-age value."));
            }
            if (!headers.presenceFlags().containsKey("Content-Security-Policy")) {
                findings = findings.with(new Finding("missing-csp", "High", "Missing CSP", "Content-Security-Policy is missing.", "Add a CSP header to reduce injection risk."));
            }
            if (!headers.presenceFlags().containsKey("X-Frame-Options")) {
                findings = findings.with(new Finding("missing-xfo", "High", "Missing X-Frame-Options", "X-Frame-Options is missing.", "Add X-Frame-Options to prevent clickjacking."));
            }
            if (!headers.presenceFlags().containsKey("X-Content-Type-Options")
                    || !headers.presenceFlags().containsKey("Referrer-Policy")
                    || !headers.presenceFlags().containsKey("Permissions-Policy")) {
                findings = findings.with(new Finding("missing-optional-header", "Medium", "Missing hardening header", "One or more hardening headers are missing.", "Add the missing header(s) to improve browser security posture."));
            }
            if (!headers.presenceFlags().containsKey("Content-Security-Policy")
                    && !headers.presenceFlags().containsKey("X-Frame-Options")) {
                findings = findings.with(new Finding("missing-headers", "High", "Missing CSP or X-Frame-Options", "Both CSP and X-Frame-Options are missing.", "Add at least one of these protection headers."));
            }
        }

        if (findings.items().isEmpty()) {
            findings = findings.with(new Finding("informational-baseline", "Low", "No issues detected", "The host appears healthy and no immediate action is required.", "Continue monitoring for future drift."));
        }

        return new Snapshot(snapshot.tls(), snapshot.headers(), findings, snapshot.metadata());
    }

    private boolean isWeakProtocol(String protocol) {
        return protocol != null && (protocol.contains("TLSv1.0") || protocol.contains("TLSv1.1") || protocol.contains("SSLv3"));
    }

    private boolean isWeakCipher(String cipher) {
        if (cipher == null) {
            return false;
        }
        String normalized = cipher.toUpperCase();
        return normalized.contains("RC4") || normalized.contains("3DES") || normalized.contains("NULL") || normalized.contains("EXPORT") || normalized.contains("DES") || normalized.contains("MD5");
    }
}
