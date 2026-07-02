# CertDrift

Intended for use only on hosts you own or have explicit authorization to test.

CertDrift is a pure Java 21 CLI project for TLS certificate analysis and HTTP security header analysis on a user-supplied list of hosts. The unique angle is drift detection: each scan is treated as a point in time, and the tool compares the latest result with the most recent stored snapshot for the same host to classify security posture changes instead of producing one-off scanner output.

## Current status

This repository currently contains the initial Maven scaffold and the composite snapshot model, which is the first step in the requested implementation order. The TLS analyzer, header analyzer, risk scoring engine, drift engine, and reporting layer are still to be implemented.

## Proposed package structure

- com.certdrift.cli - command-line entry point and argument parsing
- com.certdrift.analyzer - TLS and header scanning interfaces and implementations
- com.certdrift.model - immutable snapshot, target, finding, and metadata types
- com.certdrift.scoring - risk-scoring rubric and finding generation
- com.certdrift.storage - JSON file persistence for historical snapshots
- com.certdrift.report - CLI and HTML report rendering
- com.certdrift.drift - section-by-section drift analysis and significance classification

## Risk rubric

The scoring rubric will be implemented from the OWASP guidance cited below:

- OWASP TLS Cipher String Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/

The initial planned rubric is:

- Critical: expired certificate, TLS version <= 1.1, missing HSTS entirely on an HTTPS host
- High: self-signed certificate (unless explicitly marked internal), weak/deprecated cipher suite, missing CSP or X-Frame-Options
- Medium: certificate expiring within 30 days, missing one of X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Low: informational findings such as issuer naming or certificate lifetime details

## Build

```bash
mvn test
```

## Usage

The CLI entry point will accept a text or JSON file containing host:port pairs. The tool does not discover hosts; it only analyzes the hosts supplied by the user.

## Sample CLI output

```text
[BASELINE] example.com:443
  - Critical: certificate expired
  - High: TLS 1.0 negotiated
  - Medium: missing X-Content-Type-Options
```

## Sample HTML report

Screenshot placeholder: coming soon.
