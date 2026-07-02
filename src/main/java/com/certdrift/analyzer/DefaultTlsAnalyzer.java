package com.certdrift.analyzer;

import com.certdrift.model.HeaderSnapshot;
import com.certdrift.model.Metadata;
import com.certdrift.model.Snapshot;
import com.certdrift.model.TlsSnapshot;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

public class DefaultTlsAnalyzer implements TlsAnalyzer {

    @Override
    public Snapshot analyze(String host, int port, Metadata metadata) {
        try {
            TlsSnapshot tlsSnapshot = performHandshake(host, port);
            return new Snapshot(
                    tlsSnapshot,
                    new HeaderSnapshot(java.util.Map.of(), java.util.Map.of()),
                    null,
                    metadata
            );
        } catch (Exception ex) {
            throw new IllegalStateException("TLS analysis failed for " + host + ":" + port, ex);
        }
    }

    private TlsSnapshot performHandshake(String host, int port) throws GeneralSecurityException, IOException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, null);

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        try (SSLSocket socket = (SSLSocket) socketFactory.createSocket()) {
            socket.connect(new InetSocketAddress(host, port), 10_000);
            socket.startHandshake();

            SSLSession session = socket.getSession();
            Certificate[] peerCertificates = session.getPeerCertificates();
            List<String> chain = new ArrayList<>();
            for (Certificate certificate : peerCertificates) {
                chain.add(certificate.toString());
            }

            X509Certificate leaf = (X509Certificate) peerCertificates[0];
            Instant notAfter = leaf.getNotAfter().toInstant();
            long daysRemaining = java.time.Duration.between(Instant.now(), notAfter).toDays();

            return new TlsSnapshot(
                    chain,
                    notAfter,
                    daysRemaining,
                    isSelfSigned(leaf),
                    detectKeyAlgorithm(leaf),
                    detectKeySize(leaf),
                    detectSignatureAlgorithm(leaf),
                    session.getProtocol(),
                    session.getCipherSuite(),
                    extractSubjectAlternativeNames(leaf),
                    sanMatchesHostname(leaf, host)
            );
        }
    }

    private boolean isSelfSigned(X509Certificate certificate) {
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private String detectKeyAlgorithm(X509Certificate certificate) {
        return certificate.getPublicKey().getAlgorithm();
    }

    private Integer detectKeySize(X509Certificate certificate) {
        if (certificate.getPublicKey() instanceof java.security.interfaces.RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (certificate.getPublicKey() instanceof java.security.interfaces.ECPublicKey ec) {
            return ec.getParams().getOrder().bitLength();
        }
        return null;
    }

    private String detectSignatureAlgorithm(X509Certificate certificate) {
        return certificate.getSigAlgName();
    }

    private List<String> extractSubjectAlternativeNames(X509Certificate certificate) {
        try {
            List<String> names = new ArrayList<>();
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            if (altNames == null) {
                return List.of();
            }
            for (List<?> entry : altNames) {
                if (entry != null && entry.size() >= 2 && entry.get(0) instanceof Integer type && type == 2) {
                    Object value = entry.get(1);
                    if (value instanceof String name) {
                        names.add(name);
                    }
                }
            }
            return names;
        } catch (Exception ex) {
            return List.of();
        }
    }

    private boolean sanMatchesHostname(X509Certificate certificate, String host) {
        List<String> names = extractSubjectAlternativeNames(certificate);
        if (names.isEmpty()) {
            return false;
        }
        String normalizedHost = host.toLowerCase(Locale.ROOT);
        for (String name : names) {
            if (name.equalsIgnoreCase(normalizedHost)) {
                return true;
            }
            if (name.startsWith("*.") && normalizedHost.endsWith(name.substring(1))) {
                return true;
            }
        }
        return false;
    }
}
