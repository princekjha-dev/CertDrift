package com.certdrift.drift;

import com.certdrift.model.Snapshot;

public interface DriftEngine {
    DriftResult analyze(Snapshot current, Snapshot previous);
}
