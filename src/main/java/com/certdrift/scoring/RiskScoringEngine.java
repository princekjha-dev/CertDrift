package com.certdrift.scoring;

import com.certdrift.model.Snapshot;

public interface RiskScoringEngine {
    Snapshot score(Snapshot snapshot);
}
