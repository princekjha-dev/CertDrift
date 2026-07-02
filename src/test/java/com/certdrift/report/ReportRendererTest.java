package com.certdrift.report;

import com.certdrift.drift.DriftClassification;
import com.certdrift.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReportRendererTest {

    private final CliReportRenderer cliReportRenderer = new CliReportRenderer();
    private final HtmlReportRenderer htmlReportRenderer = new HtmlReportRenderer();

    @Test
    void rendersCliReportWithHostAndDriftSummary() {
        ReportEntry entry = new ReportEntry(
                "example.com",
                443,
                DriftClassification.REGRESSION,
                "security posture worsened: a finding became more severe.",
                List.of(new Finding("weak-cipher", "High", "Weak cipher", "The cipher suite weakened.", "Disable weak ciphers."))
        );

        String report = cliReportRenderer.render(List.of(entry));

        assertTrue(report.contains("[REGRESSION] example.com:443"));
        assertTrue(report.contains("security posture worsened"));
        assertTrue(report.contains("High"));
    }

    @Test
    void rendersSelfContainedHtmlReportWithClassificationStyles() {
        ReportEntry entry = new ReportEntry(
                "example.com",
                443,
                DriftClassification.BASELINE,
                "baseline scan: no prior snapshot was available.",
                List.of(new Finding("missing-hsts", "Critical", "Missing HSTS", "HSTS is missing.", "Add HSTS."))
        );

        String report = htmlReportRenderer.render(List.of(entry));

        assertTrue(report.contains("<html"));
        assertTrue(report.contains("<style"));
        assertTrue(report.contains("baseline"));
        assertTrue(report.contains("Missing HSTS"));
    }
}
