package com.certdrift.model;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

public record HeaderSnapshot(
        Map<String, String> values,
        Map<String, Boolean> presenceFlags
) implements Serializable {
    public HeaderSnapshot {
        values = values == null ? Map.of() : Map.copyOf(values);
        presenceFlags = presenceFlags == null ? Map.of() : Map.copyOf(presenceFlags);
    }

    public HeaderSnapshot withValue(String name, String value) {
        Map<String, String> updatedValues = new LinkedHashMap<>(values);
        updatedValues.put(name, value);
        Map<String, Boolean> updatedPresence = new LinkedHashMap<>(presenceFlags);
        updatedPresence.put(name, value != null);
        return new HeaderSnapshot(updatedValues, updatedPresence);
    }
}
