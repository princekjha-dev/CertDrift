package com.certdrift.drift;

import com.certdrift.model.Finding;
import com.certdrift.model.Findings;
import com.certdrift.model.Snapshot;
import com.certdrift.model.TlsSnapshot;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class DefaultDriftEngine implements DriftEngine {

    @Override
    public DriftResult analyze(Snapshot current, Snapshot previous) {
        if (previous == null) {
            return new DriftResult(DriftClassification.BASELINE, "baseline scan: no prior snapshot was available.", "the host was reported as a baseline scan with findings from the current snapshot.");
        }

        if (current == null) {
            return new DriftResult(DriftClassification.INFORMATIONAL, "informational drift: no current scan was available for comparison.", "the host was not part of the current run; previous history was retained.");
        }

        List<Finding> previousFindings = previous.findings() != null ? previous.findings().items() : List.of();
        List<Finding> currentFindings = current.findings() != null ? current.findings().items() : List.of();
        Map<String, Finding> previousById = previousFindings.stream().collect(Collectors.toMap(Finding::id, f -> f, (a, b) -> a));
        Map<String, Finding> currentById = currentFindings.stream().collect(Collectors.toMap(Finding::id, f -> f, (a, b) -> a));

        if (currentFindings.isEmpty() && !previousFindings.isEmpty()) {
            return new DriftResult(DriftClassification.INFORMATIONAL, "informational drift: the host was not part of the current run; previous history was retained.", "the current run did not include this host, so no new drift was reported.");
        }

        boolean severityWorsened = currentFindings.stream().anyMatch(currentFinding -> {
            Finding previousFinding = previousById.get(currentFinding.id());
            return previousFinding != null && severityRank(currentFinding.severity()) > severityRank(previousFinding.severity());
        });

        boolean severityImproved = currentFindings.stream().anyMatch(currentFinding -> {
            Finding previousFinding = previousById.get(currentFinding.id());
            return previousFinding != null && severityRank(currentFinding.severity()) < severityRank(previousFinding.severity());
        });

        if (severityWorsened) {
            return new DriftResult(DriftClassification.REGRESSION, "security posture worsened: a finding became more severe.", "the current snapshot shows a higher-severity finding than the previous snapshot.");
        }
        if (severityImproved) {
            return new DriftResult(DriftClassification.IMPROVEMENT, "security posture improved: a finding became less severe.", "the current snapshot shows a lower-severity finding than the previous snapshot.");
        }

        TlsSnapshot previousTls = previous.tls();
        TlsSnapshot currentTls = current.tls();
        if (previousTls != null && currentTls != null) {
            boolean protocolChanged = !Objects.equals(previousTls.negotiatedProtocol(), currentTls.negotiatedProtocol());
            boolean cipherChanged = !Objects.equals(previousTls.negotiatedCipherSuite(), currentTls.negotiatedCipherSuite());
            boolean certificateChanged = !Objects.equals(previousTls.notAfter(), currentTls.notAfter())
                    || !Objects.equals(previousTls.signatureAlgorithm(), currentTls.signatureAlgorithm());
            if (protocolChanged || cipherChanged) {
                return new DriftResult(DriftClassification.UNEXPECTED, "unexpected drift: tls characteristics changed without an obvious benign explanation.", "the tls protocol or cipher suite changed between scans.");
            }
            if (certificateChanged) {
                if (Math.abs(previousTls.daysRemaining() - currentTls.daysRemaining()) <= 7) {
                    return new DriftResult(DriftClassification.INFORMATIONAL, "informational drift: certificate age changed within a normal renewal window.", "the certificate changed but the change was close to a normal renewal window.");
                }
                return new DriftResult(DriftClassification.UNEXPECTED, "unexpected drift: certificate details changed outside a benign renewal window.", "the certificate changed in a way that did not look like a normal renewal.");
            }
        }

        return new DriftResult(DriftClassification.INFORMATIONAL, "informational drift: no material risk change was observed.", "the host changed in a non-material way.");
    }

    private int severityRank(String severity) {
        return switch (severity == null ? "Low" : severity.toLowerCase()) {
            case "critical" -> 3;
            case "high" -> 2;
            case "medium" -> 1;
            default -> 0;
        };
    }
}
