package com.certdrift.model;

import java.io.Serializable;

public record Snapshot(
        TlsSnapshot tls,
        HeaderSnapshot headers,
        Findings findings,
        Metadata metadata
) implements Serializable {
    public Snapshot {
        findings = findings == null ? new Findings() : findings;
    }
}
