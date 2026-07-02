package com.certdrift.analyzer;

import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;

public interface TlsAnalyzer {
    Snapshot analyze(String host, int port, Metadata metadata);
}
