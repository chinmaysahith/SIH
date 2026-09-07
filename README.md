# Email Fraud Forensic Analysis Platform

An enterprise-grade forensic analysis platform designed for investigating email fraud, spoofing, phishing, and business email compromise (BEC) campaigns.

---

### Current Status: Stage 9 — Forensic Reporting

This repository implements **Stage 0 (Project Setup)**, **Stage 1 (Upload + Quarantine Store)**, **Stage 1.5 (Job Queue)**, **Stage 2 (Email Parser)**, **Stage 3 (Rules Engine)**, **Stage 4 (ML Engine)**, **Stage 5 (IOC Analysis)**, **Stage 6 (Geo / Origin Forensics)**, **Stage 7 (Correlation Engine)**, **Stage 8 (Database + Forensic Audit Trail & Case Management)**, and **Stage 9 (Forensic Reporting)**.

```text
                                  Analyst
                                     │
                                     ▼
                             Next.js Frontend
                                     │ (multipart/form-data)
                                     ▼
                               POST /api/upload
                                     │
                               FastAPI API
                                     │
                             Quarantine Service
                              ┌──────┴──────┐
                              ▼             ▼
                        Raw Evidence     SQLite
                        + SHA-256        Case Record
                       (Byte-for-Byte)  (status: queued)
                              │             │
                              └──────┬──────┘
                                     │
                                     ▼
                                Redis Queue
                               (email_analysis)
                                     │
                                     ▼
                                RQ Worker
                              (python -m app.worker)
                                     │
                           ┌─────────┴─────────┐
                           ▼                   ▼
                   Forensic Pre-Check    Read Raw Bytes
                    Verify SHA-256      (never modified)
                           │                   │
                           └─────────┬─────────┘
                                     │
                                     ▼
                             Stage 2 Parser
                      (email.message_from_bytes)
                         ┌───────────┼───────────┐
                         ▼           ▼           ▼
                      Headers     Bodies       URLs
                     (Received) (Text/HTML) (Deduplicated)
                         │                       │
                         ▼                       ▼
                    Attachments             ParsedData
                 (data/attachments)      (SQLite Table)
                         │                       │
                         └───────────┬───────────┘
                                     │
        ┌────────────────────────────┼────────────────────────────┬────────────────────────────┐
        ▼                            ▼                            ▼                            ▼
Stage 3 Rules Engine         Stage 4 ML Engine           Stage 5 IOC Engine          Stage 6 Geo / Origin
(20 Deterministic Rules)     (TF-IDF + Logistic Reg.)    (Threat Intel Adapters)     (Hop Parser & Heuristic)
        │                            │                            │                            │
  Rules Results                  ML Signal                   IOC Results                  Geo/Origin
(Category Caps & Verdicts)    (Prob., Pred., Tokens)      (Indicator Findings)        (Origin IP, Geo, ASN)
        │                            │                            │                            │
        └────────────────────────────┼────────────────────────────┴────────────────────────────┘
                                     │
                                     ▼
                          Stage 7 Correlation Engine
                 (Multi-Signal Normalization, Weight Renorm,
                  Evidence Graph Overlap Mitigation, Conflicts)
                                     │
                                     ▼
                         Final Forensic Assessment
                (BENIGN, SUSPICIOUS, HIGH_RISK, INCONCLUSIVE)
                     (Score: 0-100, Confidence: H/M/L)
                                     │
                                     ▼
                            Forensic Post-Check
                          Verify SHA-256 Unchanged
                                     │
                                     ▼
                             status: complete
```

> **Rules Engine, ML Engine, IOC Engine, and Geo / Origin Forensics operate as strictly decoupled, independent intelligence engines. The Correlation Engine synthesizes their persisted findings into an explainable assessment with dynamic weight renormalization and cross-engine double-counting protection without touching quarantined evidence.**

---

## Forensic Integrity & Pre-Check Invariant

The quarantined file (`data/quarantine/<case_id>.eml`) is the forensic source of truth.
1. **Pre-Parse Cryptographic Check**: Before parsing, the worker calculates the disk SHA-256 of the quarantined file and compares it against `cases.sha256`. If there is any discrepancy, parsing is aborted and the case is marked `failed`.
2. **Read-Only Ingestion**: The parser and rules engine operate exclusively on extracted structured context. They never rewrite, normalize line endings, alter headers, or execute URLs or attachments.
3. **Post-Parse Verification**: Following extraction and rules evaluation, the worker verifies that the evidence file SHA-256 is 100% identical to its pre-parse value.
4. **Isolated Attachment Store**: Extracted MIME attachments are saved into an isolated directory (`data/attachments/<case_id>/`) using server-generated filenames (`attachment_001.<ext>`) with strict path traversal validation. No attachments are ever executed.

---

## Stage 3 Rules Engine Architecture

The Rules Engine provides **deterministic, explainable, and versioned (`1.0.0`) fraud scoring**:
- **Purely Deterministic**: Given identical parsed data, it will always compute identical scores and verdicts ($P + V \implies R$).
- **Anti-Double-Counting Category Caps**: Caps category contributions to avoid artificial score inflation from multiple related indicators.
- **Explainable Evidence**: Every fired rule includes machine-readable evidence, human-readable rationale, remediation guidance, and false-positive context.
- **Strictly Offline**: No external network queries (no DNS, no WHOIS, no VirusTotal, no threat intelligence APIs, no LLMs).

### Category Caps & Scoring Matrix

| Category | Cap | Rules | Description |
|---|---|---|---|
| **Header** | 20 | `RULE-HDR-001`, `RULE-HDR-002`, `RULE-HDR-003` | Hop count anomalies, missing Message-ID, From/Return-Path mismatch |
| **Sender** | 35 | `RULE-SENDER-001`, `RULE-SENDER-002`, `RULE-SENDER-003` | From vs Reply-To mismatch, display name brand impersonation, missing domain |
| **Recipient** | 10 | `RULE-RECIPIENT-001` | Undisclosed direct recipients or missing To header |
| **Content** | 35 | `RULE-CONTENT-001`, `RULE-CONTENT-002`, `RULE-CONTENT-003`, `RULE-CONTENT-004` | Urgency keywords, credential/sensitive requests, coercive threats, HTML formatting |
| **URL** | 40 | `RULE-URL-001` to `RULE-URL-005` | URLs present, insecure HTTP links, raw IP host links, obfuscation (`@` or `%`), credential auth paths |
| **Attachment** | 45 | `RULE-ATTACH-001` to `RULE-ATTACH-004` | Attachments present, dangerous extensions (`.exe`, `.scr`, `.bat`, etc.), double extensions (`.pdf.exe`), financial lures |

### Deterministic Verdict Thresholds

$$\text{Verdict} = \begin{cases} \text{BENIGN} & \text{score} < 20 \\ \text{SUSPICIOUS} & 20 \le \text{score} < 50 \\ \text{HIGH\_RISK} & \text{score} \ge 50 \end{cases}$$

---

## Database Schemas

### 1. `cases` Table
Tracks evidence metadata and pipeline lifecycle status (`uploaded` → `queued` → `processing` → `complete` / `failed`).

### 2. `parsed_data` Table (Stage 2)
Stores structured representation of headers, Received hops, plain text / HTML bodies, extracted URLs, and attachment records.

### 3. `rule_results` Table (Stage 3)
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `INTEGER` | PRIMARY KEY, AUTOINCREMENT | Record ID |
| `case_id` | `VARCHAR(64)` | FOREIGN KEY, INDEX | Associated case ID |
| `rules_engine_version` | `VARCHAR(32)` | NOT NULL | Version of Rules Engine (e.g., `1.0.0`) |
| `evaluated_timestamp` | `DATETIME` | NOT NULL | UTC evaluation timestamp |
| `total_score` | `INTEGER` | NOT NULL | Aggregate score (0–100) |
| `rules_verdict` | `VARCHAR(32)` | NOT NULL | Verdict (`BENIGN`, `SUSPICIOUS`, `HIGH_RISK`) |
| `matched_rules_count` | `INTEGER` | NOT NULL | Number of fired rules |
| `total_rules_evaluated` | `INTEGER` | NOT NULL | Total rules in registry (20) |
| `category_scores_json` | `TEXT` | NOT NULL | JSON dictionary of capped scores per category |
| `results_json` | `TEXT` | NOT NULL | Serialized list of all rule evaluation outputs with evidence |

---

---

## Stage 4 / 4.5 ML Engine Architecture

The ML Engine operates as an **independent second intelligence signal** alongside the deterministic Rules Engine:
- **Strict Decoupling**: Consumes only `ParsedData` (subject, body text, or sanitized HTML visible text). Never reads rules engine scores, triggers, or verdicts.
- **Production-Grade Real-World Training (Stage 4.5)**: Trained on verified real-world email corpora (Nazario Phishing Corpus 2024 & 2025 for phishing lures; Enron Email Dataset for legitimate corporate email).
- **Offline Reproducibility**: TF-IDF + Logistic Regression model (`phishing_model_v2.joblib`) trained offline with reproducible random seeds (`random_state=42`) and zero data leakage across stratified splits. Zero external API calls, zero LLMs, zero dynamic downloads.
- **External Robustness Benchmarking**: Independently validated against Apache SpamAssassin corpora (Easy Ham for false-positive validation: 0.82% FPR; Spam 2 for commercial bulk spam analysis).
- **Explainability**: Computes token contributions ($c_i = w_i \cdot x_i$) showing top indicators driving towards phishing or legitimate classification.
- **Fail-Safe Fallbacks**: Returns `insufficient_text` when content is under 10 characters, and `unavailable` if model artifact is missing, avoiding artificial score generation.

### Prediction & Confidence Thresholds

| Metric | Range | Value / Rating |
|---|---|---|
| **Prediction** | $< 0.30$ | `LEGITIMATE` |
| | $0.30 - 0.70$ | `UNCERTAIN` |
| | $> 0.70$ | `PHISHING` |
| **Confidence** | $|p - 0.5| \ge 0.35$ | `HIGH` |
| | $|p - 0.5| \ge 0.15$ | `MEDIUM` |
| | Else | `LOW` |

---

## Stage 5 IOC Analysis Engine Architecture

The IOC Engine provides an **adapter-based threat intelligence observation layer** that evaluates indicators already extracted in Stage 2 `ParsedData`:
- **Strict Decoupling**: Consumes only `ParsedData` indicators. Zero reliance on Rules Engine scores or ML probabilities.
- **Offline Operation**: Runs hermetically against a controlled local intelligence feed (`data/ioc/indicators.json`). No external API calls, DNS lookups, WHOIS queries, or outbound HTTP requests.
- **Extensible Adapter Architecture**: Built on the abstract `IOCSource` protocol, allowing future production feeds (VirusTotal, AbuseIPDB, URLhaus) to plug in seamlessly without rewriting the engine.
- **Forensic Attribution**: Computes and stores `feed_sha256` and `feed_version` alongside each observation for cryptographic reproducibility.
- **Critical Semantic Invariant (`NOT_FOUND` $\ne$ `KNOWN_BENIGN`)**: If an indicator is uncataloged in threat feeds, its status is strictly `not_found`, never `known_benign`.

### Supported IOC Types & Extraction Logic

| IOC Type | Source Context | Extraction & Normalization Policy |
|---|---|---|
| **`URL`** | `email_url` | Extracted from `ParsedData.urls`. Canonicalized scheme and host (lowercase), default ports stripped (80/443), path/query case preserved. |
| **`DOMAIN`** | `url_domain`, `sender_domain`, `reply_to_domain` | Extracted from URL hostnames (excluding IPs and localhost), `sender.domain`, and `Reply-To`. Lowercased, whitespace stripped, trailing dots removed. |
| **`IP`** | `url_ip` | Extracted when URL host is an IPv4 address. Validated and normalized using Python's `ipaddress` standard library (no DNS resolution). |
| **`SHA256`** | `attachment_hash` | Extracted from `ParsedData.attachments[].sha256`. Lowercased and validated to strictly 64 hexadecimal characters. |

### Threat Intelligence Feed Schema

```json
{
  "feed_version": "2026.09.1",
  "description": "Controlled local development threat intelligence feed",
  "indicators": [
    {
      "type": "DOMAIN",
      "value": "malicious-phish-bank.test",
      "status": "known_malicious",
      "confidence": 95,
      "source": "local-dev-feed",
      "reason": "Active phishing infrastructure impersonating financial institutions"
    }
  ]
}
```

> **Production Notice**: The local IOC feed is a controlled development and acceptance intelligence source. Production deployment requires continuously maintained, validated threat-intelligence feeds. IOC matches are intelligence observations and are not by themselves the final fraud verdict.

---

## API Specifications

- `POST /api/upload`: Uploads email to quarantine and enqueues background processing.
- `GET /api/cases/{case_id}/status`: Returns processing status (`queued`, `processing`, `complete`, `failed`).
- `GET /api/cases/{case_id}/parsed`: Returns parsed summary (headers, subject, URLs, attachment count, parser status).
- `GET /api/cases/{case_id}/rules`: Returns Rules Engine summary, category score breakdown, and individual rule results with evidence.
- `GET /api/cases/{case_id}/ml`: Returns ML Engine phishing probability, prediction, confidence, model status, and top feature indicators.
- `GET /api/cases/{case_id}/iocs`: Returns IOC threat intelligence findings, feed version, feed SHA-256 provenance, and summary counts.
- `GET /api/cases/{case_id}/geo`: Returns Geo / Origin forensics analysis, candidate IP hop progression, selected origin IP, approximate geolocation, ASN, and network intelligence flags (Tor, VPN, proxy, hosting).
- `GET /api/cases/{case_id}/correlation`: Returns Stage 7 Correlated Forensic Assessment, normalized risk score (0-100), confidence level, dynamic engine weights, Evidence Graph overlap mitigations, detected conflicts, top evidence items, and limitations.
- `GET /api/cases/{case_id}/timeline`: Returns chronological sequence of append-only, tamper-evident audit events with actor attribution and cryptographic block hashes.
- `GET /api/cases/{case_id}/audit/verify`: Cryptographically validates monotonic sequence continuity, cryptographic linkage, and data integrity over the case's entire event history.
- `GET /api/cases/{case_id}/analysis-runs`: Returns complete execution history of all forensic intelligence engines, execution duration, and input/output fingerprints.
- `GET /api/cases/{case_id}/provenance`: Captures immutable software versions, model versions, threat intel feeds, GeoIP databases, and correlation policy configurations.
- `GET /api/cases/{case_id}/evidence-manifest`: Returns the cryptographic catalog of primary evidence and derived analytical artifacts with individual and composite SHA-256 digests.
- `GET /api/cases/{case_id}/report`: Generates structured, deterministic JSON forensic report with content-addressed SHA-256 fingerprint.
- `GET /api/cases/{case_id}/report/html`: Generates self-contained, printable, anti-XSS escaped HTML report with zero external CDN dependencies.
- `GET /api/cases/{case_id}/report/pdf`: Generates formal, printable forensic investigation PDF with metadata tables, severity badges, and audit chain.
- `GET /api/cases/{case_id}/reports`: Returns audit log of all report generations for the case.

---

## Running with Docker Compose

```bash
docker compose up --build
```

- **Frontend**: [http://localhost:3000](http://localhost:3000)
- **Backend API**: [http://localhost:8000](http://localhost:8000)
- **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Redis**: Port 6379
- **Worker**: Background RQ worker listening on `email_analysis`

To stop:
```bash
docker compose down
```

---

## Running Automated Tests

```bash
# Run full suite (279 tests covering upload, queue, parser, rules engine, ML engine v1 & v2, IOC engine, Geo / Origin forensics, Correlation Engine, Stage 8 Audit Trail, and Stage 9 Forensic Reporting):
pytest backend/tests -v
```

All tests execute hermetically using `fakeredis` and temporary SQLite instances.
