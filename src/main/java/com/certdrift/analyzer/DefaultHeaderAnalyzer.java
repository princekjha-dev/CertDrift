package com.certdrift.analyzer;

import com.certdrift.model.HeaderSnapshot;
import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DefaultHeaderAnalyzer implements HeaderAnalyzer {

    private final HttpClient httpClient;

    public DefaultHeaderAnalyzer() {
        this(HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .build());
    }

    public DefaultHeaderAnalyzer(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public Snapshot analyze(String host, int port, Metadata metadata) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://" + host + ":" + port + "/"))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            HeaderSnapshot snapshot = parseHeaders(response.headers().map().entrySet().stream()
                    .flatMap(entry -> entry.getValue().stream().map(value -> entry.getKey() + ": " + value))
                    .toList());

            return new Snapshot(null, snapshot, null, metadata);
        } catch (Exception ex) {
            throw new IllegalStateException("Header analysis failed for " + host + ":" + port, ex);
        }
    }

    HeaderSnapshot parseHeaders(List<String> headers) {
        Map<String, String> values = new LinkedHashMap<>();
        Map<String, Boolean> presenceFlags = new LinkedHashMap<>();

        for (String header : headers) {
            int separator = header.indexOf(':');
            if (separator <= 0) {
                continue;
            }
            String name = header.substring(0, separator).trim();
            String value = header.substring(separator + 1).trim();
            values.put(name, value);
            presenceFlags.put(name, true);
        }

        return new HeaderSnapshot(values, presenceFlags);
    }
}
