package com.certdrift.analyzer;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HeaderAnalyzerTest {

    private final DefaultHeaderAnalyzer analyzer = new DefaultHeaderAnalyzer();

    @Test
    void parsesKnownSecurityHeaders() {
        var snapshot = analyzer.parseHeaders(List.of(
                "Strict-Transport-Security: max-age=31536000",
                "X-Frame-Options: DENY"
        ));

        assertNotNull(snapshot);
        assertNotNull(snapshot.values());
        assertTrue(snapshot.presenceFlags().containsKey("Strict-Transport-Security"));
        assertTrue(snapshot.presenceFlags().get("X-Frame-Options"));
        assertEquals("max-age=31536000", snapshot.values().get("Strict-Transport-Security"));
    }

    @Test
    void parsesHeaderValuesFromAProvidedResponse() {
        DefaultHeaderAnalyzer headerAnalyzer = new DefaultHeaderAnalyzer();
        var response = headerAnalyzer.parseHeaders(java.util.List.of(
                "Strict-Transport-Security: max-age=31536000",
                "Content-Security-Policy: default-src 'self'",
                "X-Frame-Options: DENY"
        ));

        assertEquals("max-age=31536000", response.values().get("Strict-Transport-Security"));
        assertEquals("default-src 'self'", response.values().get("Content-Security-Policy"));
        assertEquals("DENY", response.values().get("X-Frame-Options"));
        assertTrue(response.presenceFlags().get("X-Frame-Options"));
    }
}
