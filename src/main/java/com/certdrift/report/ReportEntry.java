package com.certdrift.report;

import com.certdrift.drift.DriftClassification;
import com.certdrift.model.Finding;

import java.util.List;

public record ReportEntry(
        String host,
        int port,
        DriftClassification classification,
        String summary,
        List<Finding> findings
) {
}
