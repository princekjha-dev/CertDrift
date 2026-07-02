package com.certdrift.storage;

import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Optional;

/**
 * Stores snapshot history in one JSON file per host:port pair.
 *
 * One file per host is simpler than a combined history file because it keeps host history isolated,
 * minimizes merge logic, and makes it easy to load only the relevant history for drift comparison.
 */
public class DefaultSnapshotStore implements SnapshotStore {

    private final Path root;
    private final ObjectMapper objectMapper;

    public DefaultSnapshotStore(Path root) {
        this.root = root;
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Override
    public void save(Snapshot snapshot) {
        saveHistory(snapshot.metadata().host(), snapshot.metadata().port(), snapshot.metadata(), snapshot);
    }

    @Override
    public Optional<Snapshot> loadLatest(String host, int port) {
        return loadHistory(host, port).flatMap(list -> list.stream().reduce((first, second) -> second));
    }

    @Override
    public Optional<Snapshot> loadByScanId(String scanId) {
        try {
            if (Files.notExists(root)) {
                return Optional.empty();
            }
            return Files.walk(root)
                    .filter(path -> path.toString().endsWith(".json"))
                    .map(this::readHistory)
                    .flatMap(Optional::stream)
                    .flatMap(List::stream)
                    .filter(snapshot -> scanId.equals(snapshot.metadata().scanId()))
                    .findFirst();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read snapshot history", e);
        }
    }

    @Override
    public void saveHistory(String host, int port, Metadata metadata, Snapshot snapshot) {
        try {
            Files.createDirectories(root);
            Path file = historyFile(host, port);
            List<Snapshot> history = loadHistory(host, port).orElse(List.of());
            history = new java.util.ArrayList<>(history);
            history.add(snapshot);
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), history);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to persist snapshot history", e);
        }
    }

    private Optional<List<Snapshot>> loadHistory(String host, int port) {
        Path file = historyFile(host, port);
        if (Files.notExists(file)) {
            return Optional.empty();
        }
        return readHistory(file);
    }

    private Optional<List<Snapshot>> readHistory(Path file) {
        try {
            return Optional.of(objectMapper.readValue(file.toFile(), objectMapper.getTypeFactory().constructCollectionType(List.class, Snapshot.class)));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private Path historyFile(String host, int port) {
        String safeHost = host.replaceAll("[^A-Za-z0-9.-]", "_");
        return root.resolve(safeHost + "_" + port + ".json");
    }
}
