package com.certdrift.cli;

import com.certdrift.analyzer.DefaultHeaderAnalyzer;
import com.certdrift.analyzer.DefaultTlsAnalyzer;
import com.certdrift.drift.DefaultDriftEngine;
import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;
import com.certdrift.report.CliReportRenderer;
import com.certdrift.report.HtmlReportRenderer;
import com.certdrift.report.ReportEntry;
import com.certdrift.scoring.DefaultRiskScoringEngine;
import com.certdrift.storage.DefaultSnapshotStore;
import com.certdrift.storage.SnapshotStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

public final class Main {
    private static final String DEFAULT_OUTPUT_DIR = "reports";
    private static final String DEFAULT_STORE_DIR = "history";

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        Path inputFile = Path.of(args[0]);
        Path outputDir = args.length > 1 ? Path.of(args[1]) : Path.of(DEFAULT_OUTPUT_DIR);
        Path storeDir = args.length > 2 ? Path.of(args[2]) : Path.of(DEFAULT_STORE_DIR);

        try {
            List<Target> targets = parseTargets(inputFile);
            if (targets.isEmpty()) {
                System.err.println("No valid hosts found in input file.");
                System.exit(1);
            }

            SnapshotStore store = new DefaultSnapshotStore(storeDir);
            DefaultTlsAnalyzer tlsAnalyzer = new DefaultTlsAnalyzer();
            DefaultHeaderAnalyzer headerAnalyzer = new DefaultHeaderAnalyzer();
            DefaultRiskScoringEngine scoringEngine = new DefaultRiskScoringEngine();
            DefaultDriftEngine driftEngine = new DefaultDriftEngine();
            CliReportRenderer cliRenderer = new CliReportRenderer();
            HtmlReportRenderer htmlRenderer = new HtmlReportRenderer();

            List<Snapshot> currentSnapshots = scanTargets(targets, tlsAnalyzer, headerAnalyzer);
            currentSnapshots = currentSnapshots.stream()
                    .map(scoringEngine::score)
                    .collect(Collectors.toList());

            List<ReportEntry> entries = new ArrayList<>();
            for (Snapshot snapshot : currentSnapshots) {
                Snapshot previousSnapshot = store.loadLatest(snapshot.metadata().host(), snapshot.metadata().port()).orElse(null);
                ReportEntry entry = createReportEntry(snapshot, previousSnapshot, driftEngine);
                entries.add(entry);
                store.save(snapshot);
            }

            Files.createDirectories(outputDir);
            Path htmlReport = outputDir.resolve("certdrift-report.html");
            Files.writeString(htmlReport, htmlRenderer.render(entries));

            System.out.print(cliRenderer.render(entries));
            System.out.println("HTML report written to " + htmlReport.toAbsolutePath());
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar certdrift.jar <hosts-file> [output-dir] [history-dir]");
        System.out.println("hosts-file must contain host:port entries, one per line.");
    }

    private static List<Target> parseTargets(Path inputFile) throws IOException {
        return Files.readAllLines(inputFile).stream()
                .map(String::trim)
                .filter(line -> !line.isBlank())
                .map(Main::parseTarget)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private static Target parseTarget(String line) {
        String normalized = line.trim();
        if (normalized.isEmpty()) {
            return null;
        }
        String[] parts = normalized.split(":", 2);
        if (parts.length == 0 || parts[0].isBlank()) {
            return null;
        }
        String host = parts[0].trim();
        int port = parts.length == 1 || parts[1].isBlank() ? 443 : parsePort(parts[1].trim());
        if (port <= 0) {
            return null;
        }
        return new Target(host, port);
    }

    private static int parsePort(String portText) {
        try {
            return Integer.parseInt(portText);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static List<Snapshot> scanTargets(List<Target> targets,
                                             DefaultTlsAnalyzer tlsAnalyzer,
                                             DefaultHeaderAnalyzer headerAnalyzer) {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Snapshot>> futures = targets.stream()
                    .map(target -> executor.submit(() -> scanTarget(target, tlsAnalyzer, headerAnalyzer)))
                    .collect(Collectors.toList());

            return futures.stream().map(future -> {
                try {
                    return future.get();
                } catch (Exception e) {
                    throw new IllegalStateException("Scan failed for a target", e);
                }
            }).collect(Collectors.toList());
        }
    }

    private static Snapshot scanTarget(Target target,
                                       DefaultTlsAnalyzer tlsAnalyzer,
                                       DefaultHeaderAnalyzer headerAnalyzer) {
        Metadata metadata = new Metadata(target.host(), target.port(), Instant.now());
        Snapshot tlsSnapshot = tlsAnalyzer.analyze(target.host(), target.port(), metadata);
        Snapshot headerSnapshot = headerAnalyzer.analyze(target.host(), target.port(), metadata);
        return new Snapshot(
                tlsSnapshot.tls(),
                headerSnapshot.headers(),
                null,
                metadata
        );
    }

    private static ReportEntry createReportEntry(Snapshot current, Snapshot previous, DefaultDriftEngine driftEngine) {
        var driftResult = driftEngine.analyze(current, previous);
        return new ReportEntry(
                current.metadata().host(),
                current.metadata().port(),
                driftResult.classification(),
                driftResult.summary(),
                current.findings().items()
        );
    }

    private record Target(String host, int port) {
    }
}
