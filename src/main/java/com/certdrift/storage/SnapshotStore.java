package com.certdrift.storage;

import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;

import java.util.Optional;

public interface SnapshotStore {
    void save(Snapshot snapshot);

    Optional<Snapshot> loadLatest(String host, int port);

    Optional<Snapshot> loadByScanId(String scanId);

    void saveHistory(String host, int port, Metadata metadata, Snapshot snapshot);
}
