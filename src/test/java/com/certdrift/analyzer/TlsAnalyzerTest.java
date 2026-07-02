package com.certdrift.analyzer;

import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class TlsAnalyzerTest {

    private final TlsAnalyzer analyzer = new DefaultTlsAnalyzer();

    @Test
    void analyzesPublicHostHandshake() {
        Snapshot snapshot = analyzer.analyze("www.google.com", 443, new Metadata("www.google.com", 443, Instant.now()));

        assertNotNull(snapshot);
        assertNotNull(snapshot.tls());
        assertFalse(snapshot.tls().certificateChain().isEmpty(), "A certificate chain should be captured");
        assertFalse(snapshot.tls().negotiatedProtocol().isBlank(), "TLS protocol should be reported");
        assertFalse(snapshot.tls().negotiatedCipherSuite().isBlank(), "Cipher suite should be reported");
        assertNotNull(snapshot.metadata());
        assertEquals("www.google.com", snapshot.metadata().host());
    }

    @Test
    void analyzesConfiguredSelfHostedHostWhenProvided() {
        String host = System.getProperty("certdrift.test.tls.host");
        String port = System.getProperty("certdrift.test.tls.port", "443");

        Assumptions.assumeTrue(host != null && !host.isBlank(),
                "Set -Dcertdrift.test.tls.host=... to exercise the self-hosted TLS test");

        Snapshot snapshot = analyzer.analyze(host, Integer.parseInt(port), new Metadata(host, Integer.parseInt(port), Instant.now()));

        assertNotNull(snapshot.tls());
        assertFalse(snapshot.tls().certificateChain().isEmpty(), "Configured host should produce a certificate chain");
        assertNotNull(snapshot.tls().notAfter());
    }
}
