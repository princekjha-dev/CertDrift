package com.certdrift.scoring;

import com.certdrift.model.Finding;
import com.certdrift.model.Findings;
import com.certdrift.model.HeaderSnapshot;
import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;
import com.certdrift.model.TlsSnapshot;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class RiskScoringEngineTest {

    private final RiskScoringEngine engine = new DefaultRiskScoringEngine();

    static Stream<Arguments> severityRules() {
        return Stream.of(
                Arguments.of("expired certificate", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().minusSeconds(86400), -1, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                        new HeaderSnapshot(Map.of(), Map.of()),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "Critical"),
                Arguments.of("tls 1.1", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 60), 60, false, "RSA", 2048, "SHA256withRSA", "TLSv1.1", "TLS_RSA_WITH_AES_128_CBC_SHA", List.of(), true),
                        new HeaderSnapshot(Map.of(), Map.of()),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "Critical"),
                Arguments.of("missing hsts", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 60), 60, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                        new HeaderSnapshot(Map.of(), Map.of()),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "Critical"),
                Arguments.of("self signed cert", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 60), 60, true, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                        new HeaderSnapshot(Map.of(), Map.of()),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "High"),
                Arguments.of("weak cipher", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 60), 60, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_RSA_WITH_RC4_128_SHA", List.of(), true),
                        new HeaderSnapshot(Map.of(), Map.of()),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "High"),
                Arguments.of("missing csp", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 60), 60, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                        new HeaderSnapshot(Map.of("Strict-Transport-Security", "max-age=31536000", "X-Frame-Options", "DENY"), Map.of("Strict-Transport-Security", true, "X-Frame-Options", true)),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "High"),
                Arguments.of("expiring soon", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 20), 20, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                        new HeaderSnapshot(Map.of(), Map.of()),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "Medium"),
                Arguments.of("missing referrer policy", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 60), 60, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                        new HeaderSnapshot(Map.of("Strict-Transport-Security", "max-age=31536000", "Content-Security-Policy", "default-src 'self'", "X-Frame-Options", "DENY", "X-Content-Type-Options", "nosniff"), Map.of("Strict-Transport-Security", true, "Content-Security-Policy", true, "X-Frame-Options", true, "X-Content-Type-Options", true)),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "Medium"),
                Arguments.of("informational", new Snapshot(
                        new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 60), 60, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                        new HeaderSnapshot(Map.of("Strict-Transport-Security", "max-age=31536000", "Content-Security-Policy", "default-src 'self'", "X-Frame-Options", "DENY", "X-Content-Type-Options", "nosniff", "Referrer-Policy", "same-origin", "Permissions-Policy", "geolocation=()"), Map.of("Strict-Transport-Security", true, "Content-Security-Policy", true, "X-Frame-Options", true, "X-Content-Type-Options", true, "Referrer-Policy", true, "Permissions-Policy", true)),
                        new Findings(),
                        new Metadata("example.com", 443, Instant.now())), "Low")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("severityRules")
    void assignsExpectedSeverity(String description, Snapshot snapshot, String expectedSeverity) {
        Snapshot scored = engine.score(snapshot);

        assertNotNull(scored);
        assertNotNull(scored.findings());
        assertFalse(scored.findings().items().isEmpty());
        assertEquals(expectedSeverity, scored.findings().items().get(0).severity());
    }
}
