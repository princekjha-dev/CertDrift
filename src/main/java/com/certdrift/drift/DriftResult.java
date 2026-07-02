package com.certdrift.drift;

public record DriftResult(
        DriftClassification classification,
        String summary,
        String details
) {
}
