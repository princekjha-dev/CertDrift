package com.certdrift.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public record Findings(List<Finding> items) implements Serializable {
    public Findings {
        items = items == null ? List.of() : List.copyOf(items);
    }

    public Findings() {
        this(List.of());
    }

    public Findings with(Finding finding) {
        List<Finding> updated = new ArrayList<>(items);
        updated.add(finding);
        return new Findings(updated);
    }
}
