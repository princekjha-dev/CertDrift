package com.certdrift.report;

import com.certdrift.drift.DriftClassification;
import com.certdrift.model.Finding;

import java.util.Comparator;
import java.util.List;

public class CliReportRenderer {

    public String render(List<ReportEntry> entries) {
        StringBuilder builder = new StringBuilder();
        entries.stream()
                .sorted(Comparator.comparingInt((ReportEntry entry) -> severityWeight(entry.classification())).reversed()
                        .thenComparing(ReportEntry::host))
                .forEach(entry -> {
                    builder.append("[")
                            .append(entry.classification().name())
                            .append("] ")
                            .append(entry.host())
                            .append(":")
                            .append(entry.port())
                            .append(System.lineSeparator());
                    builder.append("  ").append(entry.summary()).append(System.lineSeparator());
                    for (Finding finding : entry.findings()) {
                        builder.append("  - ")
                                .append(finding.severity())
                                .append(": ")
                                .append(finding.title())
                                .append(System.lineSeparator());
                    }
                });
        return builder.toString();
    }

    private int severityWeight(DriftClassification classification) {
        return switch (classification) {
            case REGRESSION -> 4;
            case IMPROVEMENT -> 3;
            case UNEXPECTED -> 2;
            case BASELINE -> 1;
            case INFORMATIONAL -> 0;
        };
    }
}
