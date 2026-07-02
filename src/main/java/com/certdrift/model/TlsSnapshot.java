package com.certdrift.model;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

public record TlsSnapshot(
        List<String> certificateChain,
        Instant notAfter,
        long daysRemaining,
        boolean selfSigned,
        String keyAlgorithm,
        Integer keySize,
        String signatureAlgorithm,
        String negotiatedProtocol,
        String negotiatedCipherSuite,
        List<String> subjectAlternativeNames,
        boolean sanMatchesHostname
) implements Serializable {
    public TlsSnapshot {
        certificateChain = List.copyOf(certificateChain == null ? List.of() : certificateChain);
        subjectAlternativeNames = List.copyOf(subjectAlternativeNames == null ? List.of() : subjectAlternativeNames);
    }
}
