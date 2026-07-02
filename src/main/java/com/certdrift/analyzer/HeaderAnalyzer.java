package com.certdrift.analyzer;

import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;

public interface HeaderAnalyzer {
    Snapshot analyze(String host, int port, Metadata metadata);
}
