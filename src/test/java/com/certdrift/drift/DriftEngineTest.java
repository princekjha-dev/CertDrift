package com.certdrift.drift;

import com.certdrift.model.Finding;
import com.certdrift.model.Findings;
import com.certdrift.model.HeaderSnapshot;
import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;
import com.certdrift.model.TlsSnapshot;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DriftEngineTest {

    private final DriftEngine engine = new DefaultDriftEngine();

    @Test
    void classifiesBaselineWithoutPriorSnapshot() {
        Snapshot current = snapshotWithFindings(List.of(new Finding("missing-hsts", "Critical", "Missing HSTS", "", "")));
        DriftResult result = engine.analyze(current, null);

        assertEquals(DriftClassification.BASELINE, result.classification());
        assertTrue(result.summary().contains("baseline"));
    }

    @Test
    void classifiesRegressionWhenSeverityWorsens() {
        Snapshot previous = snapshotWithFindings(List.of(new Finding("weak-cipher", "High", "Weak cipher", "", "")));
        Snapshot current = snapshotWithFindings(List.of(new Finding("weak-cipher", "Critical", "Weak cipher", "", "")));

        DriftResult result = engine.analyze(current, previous);

        assertEquals(DriftClassification.REGRESSION, result.classification());
        assertTrue(result.summary().contains("worsened"));
    }

    @Test
    void classifiesImprovementWhenSeverityImproves() {
        Snapshot previous = snapshotWithFindings(List.of(new Finding("weak-cipher", "Critical", "Weak cipher", "", "")));
        Snapshot current = snapshotWithFindings(List.of(new Finding("weak-cipher", "High", "Weak cipher", "", "")));

        DriftResult result = engine.analyze(current, previous);

        assertEquals(DriftClassification.IMPROVEMENT, result.classification());
        assertTrue(result.summary().contains("improved"));
    }

    @Test
    void classifiesUnexpectedWhenCertificateChangesWithoutBenignReason() {
        Snapshot previous = snapshotWithTls("TLSv1.3", "SHA256withRSA", Instant.now().plusSeconds(86400 * 100), 100);
        Snapshot current = snapshotWithTls("TLSv1.3", "SHA256withECDSA", Instant.now().plusSeconds(86400 * 30), 30);

        DriftResult result = engine.analyze(current, previous);

        assertEquals(DriftClassification.UNEXPECTED, result.classification());
        assertTrue(result.summary().contains("unexpected"));
    }

    @Test
    void classifiesInformationalForNonRiskChanges() {
        Snapshot previous = snapshotWithTls("TLSv1.3", "SHA256withRSA", Instant.now().plusSeconds(86400 * 100), 100);
        Snapshot current = snapshotWithTls("TLSv1.3", "SHA256withRSA", Instant.now().plusSeconds(86400 * 95), 95);

        DriftResult result = engine.analyze(current, previous);

        assertEquals(DriftClassification.INFORMATIONAL, result.classification());
        assertTrue(result.summary().contains("informational"));
    }

    @Test
    void retainsHistoryWhenHostRemovedFromInput() {
        Snapshot current = snapshotWithFindings(List.of());
        Snapshot previous = snapshotWithFindings(List.of(new Finding("missing-hsts", "Critical", "Missing HSTS", "", "")));
        DriftResult result = engine.analyze(current, previous);

        assertEquals(DriftClassification.INFORMATIONAL, result.classification());
    }

    private Snapshot snapshotWithFindings(List<Finding> findings) {
        return new Snapshot(
                new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400 * 60), 60, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                new HeaderSnapshot(Map.of("Strict-Transport-Security", "max-age=31536000"), Map.of("Strict-Transport-Security", true)),
                new Findings(findings),
                new Metadata("example.com", 443, Instant.now()));
    }

    private Snapshot snapshotWithTls(String protocol, String signature, Instant notAfter, long daysRemaining) {
        return new Snapshot(
                new TlsSnapshot(List.of("cert"), notAfter, daysRemaining, false, "RSA", 2048, signature, protocol, "TLS_AES_128_GCM_SHA256", List.of(), true),
                new HeaderSnapshot(Map.of(), Map.of()),
                new Findings(List.of()),
                new Metadata("example.com", 443, Instant.now()));
    }
}
