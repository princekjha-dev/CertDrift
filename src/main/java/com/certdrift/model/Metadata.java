package com.certdrift.model;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

public record Metadata(
        String host,
        int port,
        Instant scannedAt,
        String scanId
) implements Serializable {
    public Metadata(String host, int port, Instant scannedAt) {
        this(host, port, scannedAt, UUID.randomUUID().toString());
    }
}
