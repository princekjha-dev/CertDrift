package com.certdrift.storage;

import com.certdrift.model.HeaderSnapshot;
import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;
import com.certdrift.model.TlsSnapshot;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DefaultSnapshotStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void persistsAndLoadsLatestSnapshot() {
        DefaultSnapshotStore store = new DefaultSnapshotStore(tempDir);
        Snapshot snapshot = new Snapshot(
                new TlsSnapshot(List.of("cert"), Instant.now().plusSeconds(86400), 1, false, "RSA", 2048, "SHA256withRSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", List.of(), true),
                new HeaderSnapshot(java.util.Map.of(), java.util.Map.of()),
                null,
                new Metadata("example.com", 443, Instant.now())
        );

        store.save(snapshot);
        var loaded = store.loadLatest("example.com", 443);

        assertTrue(loaded.isPresent());
        assertEquals(snapshot.metadata().host(), loaded.get().metadata().host());
        assertEquals(snapshot.metadata().port(), loaded.get().metadata().port());
    }

    @Test
    void returnsEmptyWhenNoHistoryExists() {
        DefaultSnapshotStore store = new DefaultSnapshotStore(tempDir);
        assertTrue(store.loadLatest("missing.example", 443).isEmpty());
    }
}
