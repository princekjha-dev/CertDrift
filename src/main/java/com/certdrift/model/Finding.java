package com.certdrift.model;

import java.io.Serializable;

public record Finding(
        String id,
        String severity,
        String title,
        String explanation,
        String remediation
) implements Serializable {
}
