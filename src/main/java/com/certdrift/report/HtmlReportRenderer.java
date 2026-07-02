package com.certdrift.report;

import com.certdrift.drift.DriftClassification;
import com.certdrift.model.Finding;

import java.util.List;

public class HtmlReportRenderer {

    public String render(List<ReportEntry> entries) {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>")
                .append("<html lang=\"en\">")
                .append("<head><meta charset=\"utf-8\"><title>CertDrift Report</title>")
                .append("<style>")
                .append("body{font-family:Arial,sans-serif;margin:2rem;color:#1f2937;}" )
                .append(".card{border:1px solid #d1d5db;border-radius:8px;padding:1rem;margin-bottom:1rem;}" )
                .append(".regression{border-color:#dc2626;background:#fef2f2;}" )
                .append(".improvement{border-color:#16a34a;background:#f0fdf4;}" )
                .append(".unexpected{border-color:#d97706;background:#fffbeb;}" )
                .append(".baseline{border-color:#2563eb;background:#eff6ff;}" )
                .append(".informational{color:#6b7280;}")
                .append("</style></head><body>")
                .append("<h1>CertDrift Report</h1>");

        for (ReportEntry entry : entries) {
            String cssClass = cssClassFor(entry.classification());
            builder.append("<section class=\"card ").append(cssClass).append("\">");
            builder.append("<h2>").append(escape(entry.host())).append(":").append(entry.port()).append("</h2>");
            builder.append("<p><strong>").append(entry.classification().name()).append("</strong>: ")
                    .append(escape(entry.summary())).append("</p>");
            for (Finding finding : entry.findings()) {
                builder.append("<div><strong>").append(escape(finding.severity())).append("</strong>: ")
                        .append(escape(finding.title())).append("</div>");
            }
            builder.append("</section>");
        }

        builder.append("</body></html>");
        return builder.toString();
    }

    private String cssClassFor(DriftClassification classification) {
        return switch (classification) {
            case REGRESSION -> "regression";
            case IMPROVEMENT -> "improvement";
            case UNEXPECTED -> "unexpected";
            case BASELINE -> "baseline";
            case INFORMATIONAL -> "informational";
        };
    }

    private String escape(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
