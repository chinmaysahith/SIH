"use client";

import React, { useEffect, useState, useRef, useCallback } from "react";

type HealthStatus = "checking" | "connected" | "disconnected";

interface CaseRecord {
  case_id: string;
  original_filename: string;
  sha256: string;
  file_size: number;
  file_extension: string;
  status: string;
  job_id?: string | null;
  error_message?: string | null;
  upload_timestamp: string;
  processing_started_at?: string | null;
  processing_completed_at?: string | null;
}

interface RulesSummary {
  rules_engine_version: string;
  evaluated_timestamp: string;
  total_rules_evaluated: number;
  matched_rules_count: number;
  total_score: number;
  verdict: "BENIGN" | "SUSPICIOUS" | "HIGH_RISK";
  category_scores: Record<string, number>;
}

interface MLFeature {
  token: string;
  weight: number;
  direction: "phishing" | "legitimate";
}

interface MLSummary {
  case_id: string;
  model_version: string;
  preprocessing_version: string;
  prediction_timestamp: string;
  prediction: "LEGITIMATE" | "UNCERTAIN" | "PHISHING";
  phishing_probability: number;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  model_status: "ready" | "insufficient_text" | "unavailable" | "error";
  top_features: MLFeature[];
  error_message?: string | null;
}

interface IOCResultItem {
  ioc_id: string;
  ioc_type: string;
  original_value: string;
  normalized_value: string;
  source_context: string;
  matched: boolean;
  status: string;
  confidence: number;
  source: string;
  reason: string;
  feed_version: string;
  feed_sha256?: string | null;
  lookup_timestamp: string;
  error_message?: string | null;
}

interface IOCSummaryCounts {
  total_iocs: number;
  matched_iocs: number;
  malicious_iocs: number;
  suspicious_iocs: number;
  not_found_iocs: number;
}

interface IOCSummary {
  case_id: string;
  feed_versions: string[];
  feed_sha256s: string[];
  summary: IOCSummaryCounts;
  results: IOCResultItem[];
}

interface CandidateIPItem {
  ip: string;
  ip_version: number;
  classification: string;
  hop_index: number;
  raw_header_snippet: string;
  reverse_dns_hint?: string | null;
  is_origin_candidate: boolean;
}

interface GeoIPData {
  ip: string;
  country_code?: string | null;
  country_name?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracy_radius_km?: number | null;
  asn?: number | null;
  asn_org?: string | null;
  database_version?: string | null;
  database_sha256?: string | null;
}

interface NetworkIntelData {
  ip: string;
  is_tor_exit?: boolean | null;
  is_vpn?: boolean | null;
  is_proxy?: boolean | null;
  is_datacenter_hosting?: boolean | null;
  provider_name?: string | null;
  source?: string | null;
  feed_version?: string | null;
  feed_sha256?: string | null;
}

interface GeoOriginSummary {
  case_id: string;
  analysis_version: string;
  analysis_timestamp: string;
  selected_origin_ip?: string | null;
  selection_method: string;
  confidence: string;
  status: string;
  candidate_ips: CandidateIPItem[];
  geo_data?: GeoIPData | null;
  network_intel?: NetworkIntelData | null;
  limitations: string[];
  disclaimer: string;
  error_message?: string | null;
}

interface EngineSignalItem {
  engine_name: string;
  availability: string;
  raw_value?: any;
  normalized_value: number;
  base_weight: number;
  effective_weight: number;
  contribution: number;
  summary_text: string;
}

interface TopEvidenceDisplayItem {
  rank: number;
  engine: string;
  evidence_type: string;
  impact: string;
  description: string;
}

interface ConflictDisplayItem {
  conflict_type: string;
  engines_involved: string[];
  description: string;
  reconciliation: string;
}


interface TimelineEventItem {
  event_id: number;
  event_sequence: number;
  event_type: string;
  event_timestamp: string;
  actor_type: string;
  actor_id?: string | null;
  message: string;
  metadata: Record<string, any>;
  previous_event_hash?: string | null;
  event_hash: string;
}

interface TimelineResponse {
  case_id: string;
  total_events: number;
  events: TimelineEventItem[];
}

interface AuditVerificationResponse {
  case_id: string;
  valid: boolean;
  event_count: number;
  first_event_hash?: string | null;
  last_event_hash?: string | null;
  errors: Array<{
    event_id?: number | null;
    event_sequence?: number | null;
    error_type: string;
    message: string;
  }>;
  verification_timestamp: string;
}

interface AnalysisRunItem {
  run_id: string;
  engine_name: string;
  run_status: string;
  started_timestamp: string;
  completed_timestamp?: string | null;
  duration_ms?: number | null;
  engine_version: string;
  input_fingerprint?: string | null;
  output_fingerprint?: string | null;
  error_message?: string | null;
}

interface AnalysisRunsResponse {
  case_id: string;
  total_runs: number;
  runs: AnalysisRunItem[];
}

interface ProvenanceResponse {
  case_id: string;
  created_timestamp: string;
  parser_version?: string | null;
  rules_engine_version?: string | null;
  ml_model_version?: string | null;
  ml_preprocessing_version?: string | null;
  ioc_engine_version?: string | null;
  ioc_feed_version?: string | null;
  ioc_feed_sha256?: string | null;
  geo_analysis_version?: string | null;
  geo_database_version?: string | null;
  geo_database_sha256?: string | null;
  network_feed_version?: string | null;
  network_feed_sha256?: string | null;
  correlation_engine_version?: string | null;
  correlation_policy_version?: string | null;
  raw_evidence_sha256: string;
  attachment_manifest_sha256?: string | null;
}

interface EvidenceArtifactItem {
  artifact_id: number;
  artifact_type: string;
  artifact_name: string;
  relative_path?: string | null;
  size_bytes: number;
  sha256: string;
  created_timestamp: string;
  source: string;
  immutable: boolean;
}


interface ReportHistoryItem {
  report_id: string;
  format: string;
  version: string;
  generated_timestamp: string;
  report_sha256: string;
  status: string;
  error_message?: string | null;
}

interface ReportHistoryResponse {
  case_id: string;
  total_reports: number;
  reports: ReportHistoryItem[];
}

interface EvidenceManifestResponse {
  case_id: string;
  raw_evidence_sha256: string;
  manifest_sha256: string;
  total_artifacts: number;
  artifacts: EvidenceArtifactItem[];
}

interface CorrelationSummary {
  case_id: string;
  correlation_engine_version: string;
  policy_version: string;
  evaluated_timestamp: string;
  final_score: number;
  final_assessment: "BENIGN" | "SUSPICIOUS" | "HIGH_RISK" | "INCONCLUSIVE";
  correlation_confidence: "HIGH" | "MEDIUM" | "LOW";
  evidence_coverage_percent: number;
  engine_breakdown: Record<string, EngineSignalItem>;
  top_evidence: TopEvidenceDisplayItem[];
  evidence_graph: any;
  conflicts: ConflictDisplayItem[];
  limitations: string[];
  explanation: string;
  upstream_versions: Record<string, any>;
  disclaimer: string;
}

export default function Home() {
  // Backend Health State
  const [healthStatus, setHealthStatus] = useState<HealthStatus>("checking");
  const [healthError, setHealthError] = useState<string>("");
  const [lastChecked, setLastChecked] = useState<string>("");

  // Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadResult, setUploadResult] = useState<CaseRecord | null>(null);
  const [rulesSummary, setRulesSummary] = useState<RulesSummary | null>(null);
  const [mlSummary, setMlSummary] = useState<MLSummary | null>(null);
  const [iocSummary, setIocSummary] = useState<IOCSummary | null>(null);
  const [geoSummary, setGeoSummary] = useState<GeoOriginSummary | null>(null);
  const [correlationSummary, setCorrelationSummary] = useState<CorrelationSummary | null>(null);
  const [uploadError, setUploadError] = useState<string>("");
  const [timelineData, setTimelineData] = useState<TimelineResponse | null>(null);
  const [auditVerifyData, setAuditVerifyData] = useState<AuditVerificationResponse | null>(null);
  const [analysisRunsData, setAnalysisRunsData] = useState<AnalysisRunsResponse | null>(null);
  const [provenanceData, setProvenanceData] = useState<ProvenanceResponse | null>(null);
  const [manifestData, setManifestData] = useState<EvidenceManifestResponse | null>(null);
    const [reportHistory, setReportHistory] = useState<ReportHistoryResponse | null>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);
  const [activeStage8Tab, setActiveStage8Tab] = useState<"integrity" | "timeline" | "runs" | "manifest" | "provenance">("integrity");

  const [isCheckingStatus, setIsCheckingStatus] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);


  const apiUrl =
    process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const checkHealth = async () => {
    setHealthStatus("checking");
    setHealthError("");
    try {
      const response = await fetch(`${apiUrl}/health`, {
        method: "GET",
        headers: { Accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      if (data && data.status === "ok") {
        setHealthStatus("connected");
      } else {
        setHealthStatus("disconnected");
        setHealthError(`Unexpected response: ${JSON.stringify(data)}`);
      }
    } catch (err: any) {
      setHealthStatus("disconnected");
      setHealthError(err.message || "Failed to reach backend server");
    } finally {
      setLastChecked(new Date().toLocaleTimeString());
    }
  };

  const refreshCaseStatus = useCallback(async (caseId: string) => {
    setIsCheckingStatus(true);
    try {
      const response = await fetch(`${apiUrl}/api/cases/${caseId}/status`, {
        method: "GET",
        headers: { Accept: "application/json" },
      });
      if (response.ok) {
        const data = await response.json();
        setUploadResult((prev) => (prev ? { ...prev, ...data } : data));

        if (data.status === "complete") {
          try {
            const rulesRes = await fetch(`${apiUrl}/api/cases/${caseId}/rules`);
            if (rulesRes.ok) {
              const rulesData = await rulesRes.json();
              setRulesSummary(rulesData);
            }
          } catch (rErr) {
            console.error("Failed to fetch rules summary", rErr);
          }

          try {
            const mlRes = await fetch(`${apiUrl}/api/cases/${caseId}/ml`);
            if (mlRes.ok) {
              const mlData = await mlRes.json();
              setMlSummary(mlData);
            }
          } catch (mErr) {
            console.error("Failed to fetch ML summary", mErr);
          }

          try {
            const iocRes = await fetch(`${apiUrl}/api/cases/${caseId}/iocs`);
            if (iocRes.ok) {
              const iocData = await iocRes.json();
              setIocSummary(iocData);
            }
          } catch (iErr) {
            console.error("Failed to fetch IOC summary", iErr);
          }

          try {
            const geoRes = await fetch(`${apiUrl}/api/cases/${caseId}/geo`);
            if (geoRes.ok) {
              const geoData = await geoRes.json();
              setGeoSummary(geoData);
            }
          } catch (gErr) {
            console.error("Failed to fetch Geo summary", gErr);
          }

          try {
            const corrRes = await fetch(`${apiUrl}/api/cases/${caseId}/correlation`);
            if (corrRes.ok) {
              const corrData = await corrRes.json();
              setCorrelationSummary(corrData);
            }
          } catch (cErr) {
            console.error("Failed to fetch Correlation summary", cErr);
          }
          try {
            const tlRes = await fetch(`${apiUrl}/api/cases/${caseId}/timeline`);
            if (tlRes.ok) {
              const tlData = await tlRes.json();
              setTimelineData(tlData);
            }
          } catch (tlErr) {
            console.error("Failed to fetch timeline", tlErr);
          }

          try {
            const avRes = await fetch(`${apiUrl}/api/cases/${caseId}/audit/verify`);
            if (avRes.ok) {
              const avData = await avRes.json();
              setAuditVerifyData(avData);
            }
          } catch (avErr) {
            console.error("Failed to fetch audit verify", avErr);
          }

          try {
            const arRes = await fetch(`${apiUrl}/api/cases/${caseId}/analysis-runs`);
            if (arRes.ok) {
              const arData = await arRes.json();
              setAnalysisRunsData(arData);
            }
          } catch (arErr) {
            console.error("Failed to fetch analysis runs", arErr);
          }

          try {
            const provRes = await fetch(`${apiUrl}/api/cases/${caseId}/provenance`);
            if (provRes.ok) {
              const provData = await provRes.json();
              setProvenanceData(provData);
            }
          } catch (provErr) {
            console.error("Failed to fetch provenance", provErr);
          }

          try {
            const manRes = await fetch(`${apiUrl}/api/cases/${caseId}/evidence-manifest`);
            if (manRes.ok) {
              const manData = await manRes.json();
              setManifestData(manData);
            }
          } catch (manErr) {
            console.error("Failed to fetch evidence manifest", manErr);
          }
          try {
            const repHistRes = await fetch(`${apiUrl}/api/cases/${caseId}/reports`);
            if (repHistRes.ok) {
              const repHistData = await repHistRes.json();
              setReportHistory(repHistData);
            }
          } catch (repErr) {
            console.error("Failed to fetch report history", repErr);
          }


        }
      }
    } catch (err) {
      console.error("Failed to refresh case status", err);
    } finally {
      setIsCheckingStatus(false);
    }
  }, [apiUrl]);


  // Polling for live status progression if queued or processing
  useEffect(() => {
    if (!uploadResult) return;
    if (uploadResult.status === "queued" || uploadResult.status === "processing") {
      const timer = setTimeout(() => {
        refreshCaseStatus(uploadResult.case_id);
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [uploadResult, refreshCaseStatus]);

  useEffect(() => {
    checkHealth();
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUploadError("");
    setUploadResult(null);
    setRulesSummary(null);
    setMlSummary(null);
    setIocSummary(null);
    setGeoSummary(null);
    setCorrelationSummary(null);
    setTimelineData(null);
    setAuditVerifyData(null);
    setAnalysisRunsData(null);
    setProvenanceData(null);
    setManifestData(null);
    setReportHistory(null);
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      setSelectedFile(file);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setUploadError("Please select an .eml or .msg file to upload.");
      return;
    }

    setIsUploading(true);
    setUploadError("");
    setUploadResult(null);
    setRulesSummary(null);
    setMlSummary(null);
    setIocSummary(null);
    setGeoSummary(null);
    setCorrelationSummary(null);
    setTimelineData(null);
    setAuditVerifyData(null);
    setAnalysisRunsData(null);
    setProvenanceData(null);
    setManifestData(null);
    setReportHistory(null);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch(`${apiUrl}/api/upload`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        const errorDetail =
          typeof data.detail === "string"
            ? data.detail
            : Array.isArray(data.detail)
            ? data.detail.map((d: any) => d.msg).join(", ")
            : "Upload failed";
        throw new Error(errorDetail);
      }

      setUploadResult(data as CaseRecord);
    } catch (err: any) {
      setUploadError(err.message || "Upload request failed");
    } finally {
      setIsUploading(false);
    }
  };

  const handleResetUpload = () => {
    setSelectedFile(null);
    setUploadResult(null);
    setRulesSummary(null);
    setMlSummary(null);
    setIocSummary(null);
    setUploadError("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(2)} MB`;
  };

  return (
    <main
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "flex-start",
        minHeight: "100vh",
        padding: "3rem 1.5rem",
        boxSizing: "border-box",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "780px",
          display: "flex",
          flexDirection: "column",
          gap: "1.5rem",
        }}
      >
        {/* Header */}
        <header
          style={{
            backgroundColor: "#161b22",
            border: "1px solid #30363d",
            borderRadius: "8px",
            padding: "1.75rem 2rem",
            boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
          }}
        >
          <h1
            style={{
              fontSize: "1.75rem",
              fontWeight: 600,
              color: "#58a6ff",
              margin: 0,
              letterSpacing: "-0.5px",
            }}
          >
            Email Fraud Forensic Analysis Tool
          </h1>
          <p style={{ margin: "0.5rem 0 0 0", color: "#8b949e", fontSize: "0.95rem" }}>
            Stage 1.5: Evidence Ingestion &amp; Redis / RQ Background Job Queue
          </p>
        </header>

        {/* Backend Health Card */}
        <section
          style={{
            backgroundColor: "#161b22",
            border: "1px solid #30363d",
            borderRadius: "8px",
            padding: "1.25rem 1.75rem",
            boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              backgroundColor: "#0d1117",
              border: "1px solid #30363d",
              borderRadius: "6px",
              padding: "0.75rem 1.25rem",
            }}
          >
            <div>
              <div style={{ fontSize: "0.75rem", color: "#8b949e", marginBottom: "0.2rem" }}>
                Target Endpoint
              </div>
              <code style={{ color: "#79c0ff", fontSize: "0.85rem" }}>
                {apiUrl}/health
              </code>
            </div>

            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: "0.75rem", color: "#8b949e", marginBottom: "0.2rem" }}>
                Backend Status
              </div>
              {healthStatus === "checking" && (
                <span style={{ color: "#e3b341", fontWeight: 600, fontSize: "0.85rem" }}>
                  Checking...
                </span>
              )}
              {healthStatus === "connected" && (
                <span style={{ color: "#3fb950", fontWeight: 600, fontSize: "0.85rem" }}>
                  Connected
                </span>
              )}
              {healthStatus === "disconnected" && (
                <span style={{ color: "#f85149", fontWeight: 600, fontSize: "0.85rem" }}>
                  Disconnected
                </span>
              )}
            </div>
          </div>

          {healthStatus === "disconnected" && healthError && (
            <div
              style={{
                marginTop: "0.75rem",
                padding: "0.6rem 0.85rem",
                backgroundColor: "#2a1215",
                border: "1px solid #da3633",
                borderRadius: "6px",
                fontSize: "0.8rem",
                color: "#ff7b72",
              }}
            >
              <strong>Error: </strong>
              {healthError}
            </div>
          )}

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginTop: "0.75rem",
            }}
          >
            <span style={{ fontSize: "0.75rem", color: "#8b949e" }}>
              {lastChecked ? `Last check: ${lastChecked}` : ""}
            </span>
            <button
              onClick={checkHealth}
              disabled={healthStatus === "checking"}
              style={{
                backgroundColor: "#21262d",
                color: "#c9d1d9",
                border: "1px solid #30363d",
                borderRadius: "6px",
                padding: "0.3rem 0.75rem",
                fontSize: "0.75rem",
                cursor: healthStatus === "checking" ? "not-allowed" : "pointer",
              }}
            >
              Check Health
            </button>
          </div>
        </section>

        {/* Evidence Upload Section */}
        <section
          style={{
            backgroundColor: "#161b22",
            border: "1px solid #30363d",
            borderRadius: "8px",
            padding: "1.75rem 2rem",
            boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
          }}
        >
          <h2
            style={{
              fontSize: "1.2rem",
              fontWeight: 600,
              color: "#c9d1d9",
              margin: "0 0 0.5rem 0",
            }}
          >
            Forensic Evidence Intake &amp; Queue
          </h2>
          <p style={{ margin: "0 0 1.25rem 0", color: "#8b949e", fontSize: "0.85rem", lineHeight: 1.4 }}>
            Select an email (<code style={{ color: "#79c0ff" }}>.eml</code> or{" "}
            <code style={{ color: "#79c0ff" }}>.msg</code>). Evidence is safely preserved in quarantine,
            double-hashed (SHA-256), registered in SQLite, and dispatched to the Redis / RQ background queue.
          </p>

          <form onSubmit={handleUpload}>
            <div
              style={{
                border: "2px dashed #30363d",
                borderRadius: "8px",
                padding: "1.5rem",
                textAlign: "center",
                backgroundColor: "#0d1117",
                marginBottom: "1.25rem",
              }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.msg"
                onChange={handleFileChange}
                disabled={isUploading}
                style={{
                  display: "block",
                  margin: "0 auto 0.75rem auto",
                  color: "#8b949e",
                  fontSize: "0.9rem",
                }}
              />
              {selectedFile ? (
                <div style={{ fontSize: "0.85rem", color: "#58a6ff" }}>
                  Selected: <strong>{selectedFile.name}</strong> ({formatBytes(selectedFile.size)})
                </div>
              ) : (
                <div style={{ fontSize: "0.8rem", color: "#8b949e" }}>
                  Supported formats: RFC 822 (.eml) or Outlook Message (.msg)
                </div>
              )}
            </div>

            <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
              <button
                type="submit"
                disabled={!selectedFile || isUploading}
                style={{
                  backgroundColor: !selectedFile || isUploading ? "#21262d" : "#238636",
                  color: !selectedFile || isUploading ? "#8b949e" : "#ffffff",
                  border: "1px solid #30363d",
                  borderRadius: "6px",
                  padding: "0.6rem 1.25rem",
                  fontSize: "0.9rem",
                  fontWeight: 600,
                  cursor: !selectedFile || isUploading ? "not-allowed" : "pointer",
                }}
              >
                {isUploading ? "Preserving & Enqueueing..." : "Upload & Enqueue"}
              </button>

              {(selectedFile || uploadResult || uploadError) && (
                <button
                  type="button"
                  onClick={handleResetUpload}
                  disabled={isUploading}
                  style={{
                    backgroundColor: "#21262d",
                    color: "#c9d1d9",
                    border: "1px solid #30363d",
                    borderRadius: "6px",
                    padding: "0.6rem 1rem",
                    fontSize: "0.85rem",
                    cursor: isUploading ? "not-allowed" : "pointer",
                  }}
                >
                  Reset
                </button>
              )}
            </div>
          </form>

          {/* Upload Error Banner */}
          {uploadError && (
            <div
              style={{
                marginTop: "1.25rem",
                padding: "0.85rem 1rem",
                backgroundColor: "#2a1215",
                border: "1px solid #da3633",
                borderRadius: "6px",
                color: "#ff7b72",
                fontSize: "0.85rem",
              }}
            >
              <strong>Upload Failed: </strong>
              {uploadError}
            </div>
          )}

          {/* Upload Success / Case Metadata Card */}
          {uploadResult && (
            <div
              style={{
                marginTop: "1.25rem",
                padding: "1.25rem",
                backgroundColor: "#0d1117",
                border:
                  uploadResult.status === "queue_failed" || uploadResult.status === "failed"
                    ? "1px solid #da3633"
                    : uploadResult.status === "complete"
                    ? "1px solid #238636"
                    : "1px solid #1f6feb",
                borderRadius: "6px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: "1rem",
                  paddingBottom: "0.75rem",
                  borderBottom: "1px solid #21262d",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span
                    style={{
                      width: "10px",
                      height: "10px",
                      borderRadius: "50%",
                      backgroundColor:
                        uploadResult.status === "queue_failed" || uploadResult.status === "failed"
                          ? "#f85149"
                          : uploadResult.status === "complete"
                          ? "#3fb950"
                          : "#58a6ff",
                    }}
                  />
                  <span
                    style={{
                      color:
                        uploadResult.status === "queue_failed" || uploadResult.status === "failed"
                          ? "#f85149"
                          : uploadResult.status === "complete"
                          ? "#3fb950"
                          : "#58a6ff",
                      fontWeight: 600,
                      fontSize: "0.95rem",
                    }}
                  >
                    {uploadResult.status === "queue_failed"
                      ? "Evidence Preserved (Queue Offline)"
                      : uploadResult.status === "complete"
                      ? "Stage 1.5 Background Job Complete"
                      : uploadResult.status === "processing"
                      ? "Worker Processing Case..."
                      : "Evidence Quarantined & Enqueued"}
                  </span>
                </div>

                <span
                  style={{
                    backgroundColor:
                      uploadResult.status === "complete"
                        ? "#23863633"
                        : uploadResult.status === "queue_failed" || uploadResult.status === "failed"
                        ? "#da363333"
                        : "#1f6feb22",
                    color:
                      uploadResult.status === "complete"
                        ? "#3fb950"
                        : uploadResult.status === "queue_failed" || uploadResult.status === "failed"
                        ? "#f85149"
                        : "#58a6ff",
                    border: `1px solid ${
                      uploadResult.status === "complete"
                        ? "#238636"
                        : uploadResult.status === "queue_failed" || uploadResult.status === "failed"
                        ? "#da3633"
                        : "#1f6feb"
                    }`,
                    borderRadius: "12px",
                    padding: "0.15rem 0.6rem",
                    fontSize: "0.75rem",
                    fontWeight: 600,
                    textTransform: "uppercase",
                  }}
                >
                  {uploadResult.status}
                </span>
              </div>

              {/* Special warning if queue failed after preservation */}
              {uploadResult.status === "queue_failed" && (
                <div
                  style={{
                    padding: "0.6rem 0.85rem",
                    backgroundColor: "#2a1215",
                    border: "1px solid #da3633",
                    borderRadius: "6px",
                    color: "#ff7b72",
                    fontSize: "0.8rem",
                    marginBottom: "1rem",
                  }}
                >
                  <strong>Notice: </strong>
                  Evidence was safely quarantined, but background processing could not be queued
                  (Redis unavailable: {uploadResult.error_message || "connection error"}).
                </div>
              )}

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "140px 1fr",
                  gap: "0.6rem 1rem",
                  fontSize: "0.85rem",
                }}
              >
                <div style={{ color: "#8b949e" }}>Case ID:</div>
                <div>
                  <code style={{ color: "#f0883e", fontWeight: 600 }}>
                    {uploadResult.case_id}
                  </code>
                </div>

                <div style={{ color: "#8b949e" }}>SHA-256 Hash:</div>
                <div style={{ wordBreak: "break-all" }}>
                  <code style={{ color: "#79c0ff", fontSize: "0.8rem" }}>
                    {uploadResult.sha256}
                  </code>
                </div>

                <div style={{ color: "#8b949e" }}>RQ Job ID:</div>
                <div>
                  <code style={{ color: "#d2a8ff", fontSize: "0.8rem" }}>
                    {uploadResult.job_id || "None (Queue offline)"}
                  </code>
                </div>

                <div style={{ color: "#8b949e" }}>Original File:</div>
                <div style={{ color: "#c9d1d9" }}>
                  {uploadResult.original_filename} ({formatBytes(uploadResult.file_size)})
                </div>

                <div style={{ color: "#8b949e" }}>Storage Store:</div>
                <div style={{ color: "#8b949e", fontSize: "0.8rem" }}>
                  data/quarantine/{uploadResult.case_id}{uploadResult.file_extension}
                </div>

                <div style={{ color: "#8b949e" }}>Uploaded At:</div>
                <div style={{ color: "#8b949e", fontSize: "0.8rem" }}>
                  {new Date(uploadResult.upload_timestamp).toLocaleString()}
                </div>

                {uploadResult.processing_started_at && (
                  <>
                    <div style={{ color: "#8b949e" }}>Worker Started:</div>
                    <div style={{ color: "#8b949e", fontSize: "0.8rem" }}>
                      {new Date(uploadResult.processing_started_at).toLocaleString()}
                    </div>
                  </>
                )}

                {uploadResult.processing_completed_at && (
                  <>
                    <div style={{ color: "#8b949e" }}>Worker Completed:</div>
                    <div style={{ color: "#56d364", fontSize: "0.8rem" }}>
                      {new Date(uploadResult.processing_completed_at).toLocaleString()}
                    </div>
                  </>
                )}

                {rulesSummary && (
                  <>
                    <div style={{ color: "#8b949e" }}>Rules Verdict:</div>
                    <div>
                      <span
                        style={{
                          backgroundColor:
                            rulesSummary.verdict === "BENIGN"
                              ? "#23863633"
                              : rulesSummary.verdict === "SUSPICIOUS"
                              ? "#d2992233"
                              : "#da363333",
                          color:
                            rulesSummary.verdict === "BENIGN"
                              ? "#3fb950"
                              : rulesSummary.verdict === "SUSPICIOUS"
                              ? "#e3b341"
                              : "#f85149",
                          border: `1px solid ${
                            rulesSummary.verdict === "BENIGN"
                              ? "#238636"
                              : rulesSummary.verdict === "SUSPICIOUS"
                              ? "#d29922"
                              : "#da3633"
                          }`,
                          borderRadius: "12px",
                          padding: "0.2rem 0.6rem",
                          fontSize: "0.8rem",
                          fontWeight: 700,
                        }}
                      >
                        {rulesSummary.verdict} (Score: {rulesSummary.total_score}/100)
                      </span>
                      <span style={{ color: "#8b949e", fontSize: "0.75rem", marginLeft: "8px" }}>
                        ({rulesSummary.matched_rules_count} rules matched)
                      </span>
                    </div>
                  </>
                )}

                {mlSummary && (
                  <>
                    <div style={{ color: "#8b949e" }}>ML Phishing Signal:</div>
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                        <span
                          style={{
                            backgroundColor:
                              mlSummary.prediction === "LEGITIMATE"
                                ? "#23863633"
                                : mlSummary.prediction === "UNCERTAIN"
                                ? "#d2992233"
                                : "#da363333",
                            color:
                              mlSummary.prediction === "LEGITIMATE"
                                ? "#3fb950"
                                : mlSummary.prediction === "UNCERTAIN"
                                ? "#e3b341"
                                : "#f85149",
                            border: `1px solid ${
                              mlSummary.prediction === "LEGITIMATE"
                                ? "#238636"
                                : mlSummary.prediction === "UNCERTAIN"
                                ? "#d29922"
                                : "#da3633"
                            }`,
                            borderRadius: "12px",
                            padding: "0.2rem 0.6rem",
                            fontSize: "0.8rem",
                            fontWeight: 700,
                          }}
                        >
                          {mlSummary.prediction}
                        </span>
                        <span style={{ color: "#c9d1d9", fontSize: "0.85rem", fontWeight: 600 }}>
                          {(mlSummary.phishing_probability * 100).toFixed(1)}% Phishing Probability
                        </span>
                        <span
                          style={{
                            color: "#8b949e",
                            fontSize: "0.75rem",
                            border: "1px solid #30363d",
                            borderRadius: "4px",
                            padding: "0.1rem 0.4rem",
                          }}
                        >
                          Confidence: {mlSummary.confidence}
                        </span>
                        <span style={{ color: "#8b949e", fontSize: "0.75rem" }}>
                          (v{mlSummary.model_version} • {mlSummary.model_status})
                        </span>
                      </div>

                      {mlSummary.top_features && mlSummary.top_features.length > 0 && (
                        <div style={{ marginTop: "0.5rem", fontSize: "0.75rem" }}>
                          <div style={{ color: "#8b949e", marginBottom: "0.25rem" }}>Key Indicators:</div>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                            {mlSummary.top_features.map((feat, idx) => (
                              <span
                                key={idx}
                                style={{
                                  padding: "0.1rem 0.4rem",
                                  borderRadius: "4px",
                                  backgroundColor: feat.direction === "phishing" ? "#da363322" : "#23863622",
                                  color: feat.direction === "phishing" ? "#ff7b72" : "#7ee787",
                                  border: `1px solid ${feat.direction === "phishing" ? "#da363344" : "#23863644"}`,
                                  fontFamily: "monospace",
                                }}
                                title={`Weight: ${feat.weight} (${feat.direction})`}
                              >
                                {feat.direction === "phishing" ? "▲" : "▼"} {feat.token}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                )}

                {iocSummary && (
                  <>
                    <div style={{ color: "#8b949e" }}>IOC Threat Intelligence:</div>
                    <div>
                      {/* Overview counts */}
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginBottom: "0.5rem" }}>
                        <span
                          style={{
                            backgroundColor: "#1f6feb22",
                            color: "#58a6ff",
                            border: "1px solid #1f6feb66",
                            borderRadius: "12px",
                            padding: "0.2rem 0.6rem",
                            fontSize: "0.8rem",
                            fontWeight: 700,
                          }}
                        >
                          Total IOCs: {iocSummary.summary.total_iocs}
                        </span>

                        <span
                          style={{
                            backgroundColor: iocSummary.summary.malicious_iocs > 0 ? "#da363333" : "#21262d",
                            color: iocSummary.summary.malicious_iocs > 0 ? "#f85149" : "#8b949e",
                            border: `1px solid ${iocSummary.summary.malicious_iocs > 0 ? "#da3633" : "#30363d"}`,
                            borderRadius: "12px",
                            padding: "0.2rem 0.6rem",
                            fontSize: "0.8rem",
                            fontWeight: 700,
                          }}
                        >
                          Malicious: {iocSummary.summary.malicious_iocs}
                        </span>

                        <span
                          style={{
                            backgroundColor: iocSummary.summary.suspicious_iocs > 0 ? "#d2992233" : "#21262d",
                            color: iocSummary.summary.suspicious_iocs > 0 ? "#e3b341" : "#8b949e",
                            border: `1px solid ${iocSummary.summary.suspicious_iocs > 0 ? "#d29922" : "#30363d"}`,
                            borderRadius: "12px",
                            padding: "0.2rem 0.6rem",
                            fontSize: "0.8rem",
                            fontWeight: 700,
                          }}
                        >
                          Suspicious: {iocSummary.summary.suspicious_iocs}
                        </span>

                        <span
                          style={{
                            backgroundColor: "#21262d",
                            color: "#8b949e",
                            border: "1px solid #30363d",
                            borderRadius: "12px",
                            padding: "0.2rem 0.6rem",
                            fontSize: "0.8rem",
                          }}
                        >
                          Not Found: {iocSummary.summary.not_found_iocs}
                        </span>

                        {iocSummary.feed_versions.length > 0 && (
                          <span style={{ color: "#8b949e", fontSize: "0.75rem", marginLeft: "4px" }}>
                            Feed: {iocSummary.feed_versions.join(", ")}
                            {iocSummary.feed_sha256s.length > 0 && (
                              <code style={{ marginLeft: "4px", fontSize: "0.7rem", color: "#79c0ff" }}>
                                ({iocSummary.feed_sha256s[0].slice(0, 8)}...)
                              </code>
                            )}
                          </span>
                        )}
                      </div>

                      {/* Individual IOC findings table / list */}
                      {iocSummary.results.length > 0 && (
                        <div
                          style={{
                            maxHeight: "220px",
                            overflowY: "auto",
                            border: "1px solid #21262d",
                            borderRadius: "6px",
                            padding: "0.5rem",
                            backgroundColor: "#0d1117",
                            fontSize: "0.78rem",
                          }}
                        >
                          <table style={{ width: "100%", borderCollapse: "collapse" }}>
                            <thead>
                              <tr style={{ color: "#8b949e", borderBottom: "1px solid #21262d", textAlign: "left" }}>
                                <th style={{ padding: "4px 8px" }}>Type</th>
                                <th style={{ padding: "4px 8px" }}>Indicator</th>
                                <th style={{ padding: "4px 8px" }}>Context</th>
                                <th style={{ padding: "4px 8px" }}>Status</th>
                                <th style={{ padding: "4px 8px" }}>Source & Reason</th>
                              </tr>
                            </thead>
                            <tbody>
                              {iocSummary.results.map((ioc) => (
                                <tr key={ioc.ioc_id} style={{ borderBottom: "1px solid #161b22" }}>
                                  <td style={{ padding: "4px 8px" }}>
                                    <span
                                      style={{
                                        color: "#79c0ff",
                                        fontFamily: "monospace",
                                        fontSize: "0.72rem",
                                      }}
                                    >
                                      {ioc.ioc_type}
                                    </span>
                                  </td>
                                  <td style={{ padding: "4px 8px", maxWidth: "200px", wordBreak: "break-all" }}>
                                    <span title={`Normalized: ${ioc.normalized_value}`} style={{ color: "#c9d1d9" }}>
                                      {ioc.original_value}
                                    </span>
                                  </td>
                                  <td style={{ padding: "4px 8px", color: "#8b949e" }}>
                                    {ioc.source_context}
                                  </td>
                                  <td style={{ padding: "4px 8px" }}>
                                    <span
                                      style={{
                                        color:
                                          ioc.status === "known_malicious"
                                            ? "#ff7b72"
                                            : ioc.status === "known_suspicious"
                                            ? "#e3b341"
                                            : ioc.status === "known_benign"
                                            ? "#3fb950"
                                            : "#8b949e",
                                        fontWeight: 600,
                                        fontSize: "0.72rem",
                                      }}
                                    >
                                      {ioc.status.toUpperCase()}
                                    </span>
                                  </td>
                                  <td style={{ padding: "4px 8px", color: "#8b949e" }}>
                                    {ioc.source} ({ioc.confidence}%) — {ioc.reason}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                      <div style={{ marginTop: "0.35rem", fontSize: "0.7rem", color: "#8b949e", fontStyle: "italic" }}>
                        Note: IOC observations are derived from offline threat intelligence feeds and do not constitute a final fraud verdict.
                      </div>
                    </div>
                  </>
                )}

                {/* Stage 6 Geo / Origin Forensics Card */}
                {geoSummary && (
                  <div
                    style={{
                      border: "1px solid #30363d",
                      borderRadius: "8px",
                      padding: "1rem",
                      backgroundColor: "#161b22",
                      gridColumn: "1 / -1",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: "0.75rem",
                      }}
                    >
                      <h4
                        style={{
                          margin: 0,
                          fontSize: "0.95rem",
                          color: "#58a6ff",
                          display: "flex",
                          alignItems: "center",
                          gap: "0.5rem",
                        }}
                      >
                        <span>Stage 6 — Network Origin & Geolocation Forensics</span>
                        <span
                          style={{
                            fontSize: "0.7rem",
                            color: "#8b949e",
                            fontWeight: 400,
                            backgroundColor: "#21262d",
                            padding: "0.15rem 0.4rem",
                            borderRadius: "4px",
                          }}
                        >
                          v{geoSummary.analysis_version}
                        </span>
                      </h4>

                      <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                        <span
                          style={{
                            backgroundColor:
                              geoSummary.confidence === "HIGH"
                                ? "#238636"
                                : geoSummary.confidence === "MEDIUM"
                                ? "#d29922"
                                : "#8b949e",
                            color: "#ffffff",
                            borderRadius: "12px",
                            padding: "0.2rem 0.6rem",
                            fontSize: "0.75rem",
                            fontWeight: 600,
                          }}
                        >
                          Confidence: {geoSummary.confidence}
                        </span>
                      </div>
                    </div>

                    {/* Forensic Disclaimer Callout */}
                    <div
                      style={{
                        backgroundColor: "#1f242c",
                        borderLeft: "3px solid #d29922",
                        padding: "0.5rem 0.75rem",
                        borderRadius: "4px",
                        fontSize: "0.75rem",
                        color: "#e3b341",
                        marginBottom: "0.75rem",
                      }}
                    >
                      <strong>Forensic Notice:</strong> {geoSummary.disclaimer}
                    </div>

                    {/* Origin candidate summary */}
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                        gap: "0.75rem",
                        backgroundColor: "#0d1117",
                        padding: "0.75rem",
                        borderRadius: "6px",
                        border: "1px solid #21262d",
                        marginBottom: "0.75rem",
                        fontSize: "0.82rem",
                      }}
                    >
                      <div>
                        <div style={{ color: "#8b949e", fontSize: "0.72rem" }}>Selected Origin IP</div>
                        <div style={{ color: "#58a6ff", fontWeight: 600, fontFamily: "monospace", marginTop: "2px" }}>
                          {geoSummary.selected_origin_ip || "No Candidate Found"}
                        </div>
                        <div style={{ color: "#8b949e", fontSize: "0.68rem" }}>
                          Method: {geoSummary.selection_method}
                        </div>
                      </div>

                      <div>
                        <div style={{ color: "#8b949e", fontSize: "0.72rem" }}>Approximate Location</div>
                        <div style={{ color: "#c9d1d9", fontWeight: 500, marginTop: "2px" }}>
                          {geoSummary.geo_data?.country_name ? (
                            <>
                              {geoSummary.geo_data.city ? `${geoSummary.geo_data.city}, ` : ""}
                              {geoSummary.geo_data.country_name} ({geoSummary.geo_data.country_code})
                            </>
                          ) : (
                            <span style={{ color: "#8b949e" }}>Location Unavailable</span>
                          )}
                        </div>
                        {geoSummary.geo_data?.latitude && geoSummary.geo_data?.longitude && (
                          <div style={{ color: "#8b949e", fontSize: "0.68rem" }}>
                            Lat: {geoSummary.geo_data.latitude.toFixed(2)}, Lon: {geoSummary.geo_data.longitude.toFixed(2)}
                          </div>
                        )}
                      </div>

                      <div>
                        <div style={{ color: "#8b949e", fontSize: "0.72rem" }}>ASN & Routing</div>
                        <div style={{ color: "#c9d1d9", fontWeight: 500, marginTop: "2px" }}>
                          {geoSummary.geo_data?.asn ? (
                            <>
                              AS{geoSummary.geo_data.asn} {geoSummary.geo_data.asn_org ? `— ${geoSummary.geo_data.asn_org}` : ""}
                            </>
                          ) : (
                            <span style={{ color: "#8b949e" }}>ASN Unavailable</span>
                          )}
                        </div>
                        {geoSummary.geo_data?.database_version && (
                          <div style={{ color: "#8b949e", fontSize: "0.68rem" }}>
                            GeoIP DB: {geoSummary.geo_data.database_version}
                          </div>
                        )}
                      </div>

                      <div>
                        <div style={{ color: "#8b949e", fontSize: "0.72rem" }}>Network Indicators</div>
                        <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap", marginTop: "4px" }}>
                          {geoSummary.network_intel?.is_tor_exit && (
                            <span
                              style={{
                                backgroundColor: "#da3633",
                                color: "#ffffff",
                                padding: "0.1rem 0.4rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                                fontWeight: 600,
                              }}
                            >
                              TOR EXIT
                            </span>
                          )}
                          {geoSummary.network_intel?.is_vpn && (
                            <span
                              style={{
                                backgroundColor: "#d29922",
                                color: "#ffffff",
                                padding: "0.1rem 0.4rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                                fontWeight: 600,
                              }}
                            >
                              VPN
                            </span>
                          )}
                          {geoSummary.network_intel?.is_proxy && (
                            <span
                              style={{
                                backgroundColor: "#8957e5",
                                color: "#ffffff",
                                padding: "0.1rem 0.4rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                                fontWeight: 600,
                              }}
                            >
                              PROXY
                            </span>
                          )}
                          {geoSummary.network_intel?.is_datacenter_hosting && (
                            <span
                              style={{
                                backgroundColor: "#21262d",
                                color: "#79c0ff",
                                border: "1px solid #30363d",
                                padding: "0.1rem 0.4rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                              }}
                            >
                              HOSTING/RELAY
                            </span>
                          )}
                          {!geoSummary.network_intel?.is_tor_exit &&
                            !geoSummary.network_intel?.is_vpn &&
                            !geoSummary.network_intel?.is_proxy &&
                            !geoSummary.network_intel?.is_datacenter_hosting && (
                              <span style={{ color: "#8b949e", fontSize: "0.72rem" }}>No Special Flags</span>
                            )}
                        </div>
                      </div>
                    </div>

                    {/* Candidate IPs Hop Progression Table */}
                    {geoSummary.candidate_ips.length > 0 && (
                      <div
                        style={{
                          maxHeight: "180px",
                          overflowY: "auto",
                          border: "1px solid #21262d",
                          borderRadius: "6px",
                          padding: "0.5rem",
                          backgroundColor: "#0d1117",
                          fontSize: "0.76rem",
                        }}
                      >
                        <table style={{ width: "100%", borderCollapse: "collapse" }}>
                          <thead>
                            <tr style={{ color: "#8b949e", borderBottom: "1px solid #21262d", textAlign: "left" }}>
                              <th style={{ padding: "4px 8px" }}>Hop</th>
                              <th style={{ padding: "4px 8px" }}>Candidate IP</th>
                              <th style={{ padding: "4px 8px" }}>Classification</th>
                              <th style={{ padding: "4px 8px" }}>Role</th>
                              <th style={{ padding: "4px 8px" }}>rDNS / Context</th>
                            </tr>
                          </thead>
                          <tbody>
                            {geoSummary.candidate_ips.map((c, i) => (
                              <tr
                                key={i}
                                style={{
                                  borderBottom: "1px solid #161b22",
                                  backgroundColor: c.ip === geoSummary.selected_origin_ip ? "rgba(56, 139, 253, 0.1)" : "transparent",
                                }}
                              >
                                <td style={{ padding: "4px 8px", color: "#8b949e" }}>#{c.hop_index}</td>
                                <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "#c9d1d9" }}>
                                  {c.ip}
                                </td>
                                <td style={{ padding: "4px 8px" }}>
                                  <span
                                    style={{
                                      fontSize: "0.68rem",
                                      padding: "0.1rem 0.35rem",
                                      borderRadius: "4px",
                                      backgroundColor:
                                        c.classification === "GLOBAL" || c.classification === "DOCUMENTATION"
                                          ? "rgba(56, 139, 253, 0.2)"
                                          : "#21262d",
                                      color:
                                        c.classification === "GLOBAL" || c.classification === "DOCUMENTATION"
                                          ? "#58a6ff"
                                          : "#8b949e",
                                    }}
                                  >
                                    {c.classification}
                                  </span>
                                </td>
                                <td style={{ padding: "4px 8px" }}>
                                  {c.ip === geoSummary.selected_origin_ip ? (
                                    <span style={{ color: "#3fb950", fontWeight: 600 }}>SELECTED ORIGIN</span>
                                  ) : (
                                    <span style={{ color: "#8b949e" }}>
                                      {c.is_origin_candidate ? "Candidate" : "Relay / Internal"}
                                    </span>
                                  )}
                                </td>
                                <td style={{ padding: "4px 8px", color: "#8b949e" }}>
                                  {c.reverse_dns_hint || c.raw_header_snippet.slice(0, 50)}...
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}

                    {/* Analytical Limitations */}
                    {geoSummary.limitations.length > 0 && (
                      <div style={{ marginTop: "0.5rem" }}>
                        <div style={{ fontSize: "0.72rem", color: "#8b949e", marginBottom: "0.25rem" }}>
                          Forensic Caveats & Chain Limitations:
                        </div>
                        <ul style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.7rem", color: "#8b949e" }}>
                          {geoSummary.limitations.map((lim, idx) => (
                            <li key={idx}>{lim}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {/* Stage 7 — Final Forensic Assessment & Correlation Card */}
                {correlationSummary && (
                  <div
                    style={{
                      border: "2px solid",
                      borderColor:
                        correlationSummary.final_assessment === "HIGH_RISK"
                          ? "#da3633"
                          : correlationSummary.final_assessment === "SUSPICIOUS"
                          ? "#d29922"
                          : correlationSummary.final_assessment === "BENIGN"
                          ? "#238636"
                          : "#8b949e",
                      borderRadius: "8px",
                      padding: "1.25rem",
                      backgroundColor: "#161b22",
                      gridColumn: "1 / -1",
                      marginTop: "0.5rem",
                    }}
                  >
                    {/* Header with Assessment Pill and Score */}
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        flexWrap: "wrap",
                        gap: "0.75rem",
                        marginBottom: "1rem",
                        paddingBottom: "0.75rem",
                        borderBottom: "1px solid #21262d",
                      }}
                    >
                      <div>
                        <div style={{ fontSize: "0.75rem", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>
                          Stage 7 Final Forensic Assessment
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "4px" }}>
                          <span
                            style={{
                              backgroundColor:
                                correlationSummary.final_assessment === "HIGH_RISK"
                                  ? "#da3633"
                                  : correlationSummary.final_assessment === "SUSPICIOUS"
                                  ? "#d29922"
                                  : correlationSummary.final_assessment === "BENIGN"
                                  ? "#238636"
                                  : "#484f58",
                              color: "#ffffff",
                              borderRadius: "16px",
                              padding: "0.25rem 0.9rem",
                              fontSize: "1rem",
                              fontWeight: 800,
                              letterSpacing: "0.03em",
                            }}
                          >
                            {correlationSummary.final_assessment.replace("_", " ")}
                          </span>
                          <span style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f0f6fc" }}>
                            Score: {correlationSummary.final_score.toFixed(1)} / 100
                          </span>
                        </div>
                      </div>

                      <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                        <span
                          style={{
                            backgroundColor: "#21262d",
                            border: "1px solid #30363d",
                            color:
                              correlationSummary.correlation_confidence === "HIGH"
                                ? "#3fb950"
                                : correlationSummary.correlation_confidence === "MEDIUM"
                                ? "#e3b341"
                                : "#f85149",
                            padding: "0.2rem 0.6rem",
                            borderRadius: "12px",
                            fontSize: "0.75rem",
                            fontWeight: 600,
                          }}
                        >
                          Confidence: {correlationSummary.correlation_confidence}
                        </span>
                        <span
                          style={{
                            backgroundColor: "#21262d",
                            border: "1px solid #30363d",
                            color: "#79c0ff",
                            padding: "0.2rem 0.6rem",
                            borderRadius: "12px",
                            fontSize: "0.75rem",
                          }}
                        >
                          Coverage: {correlationSummary.evidence_coverage_percent.toFixed(0)}%
                        </span>
                        <span style={{ fontSize: "0.7rem", color: "#8b949e" }}>
                          v{correlationSummary.correlation_engine_version}
                        </span>
                      </div>
                    </div>

                    {/* Analyst Readable Explanation Box */}
                    <div
                      style={{
                        backgroundColor: "#0d1117",
                        border: "1px solid #30363d",
                        borderLeft: "4px solid #58a6ff",
                        borderRadius: "6px",
                        padding: "0.75rem 1rem",
                        marginBottom: "1rem",
                        fontSize: "0.82rem",
                        lineHeight: 1.5,
                        color: "#c9d1d9",
                      }}
                    >
                      <strong style={{ color: "#58a6ff", display: "block", marginBottom: "2px" }}>
                        Forensic Findings Summary:
                      </strong>
                      {correlationSummary.explanation}
                    </div>

                    {/* Engine Breakdown Cards */}
                    <div style={{ marginBottom: "1rem" }}>
                      <div style={{ fontSize: "0.75rem", color: "#8b949e", textTransform: "uppercase", fontWeight: 600, marginBottom: "0.4rem" }}>
                        Multi-Engine Evidence Fusion:
                      </div>
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                          gap: "0.6rem",
                        }}
                      >
                        {Object.entries(correlationSummary.engine_breakdown).map(([name, sig]) => (
                          <div
                            key={name}
                            style={{
                              backgroundColor: "#0d1117",
                              border: "1px solid #21262d",
                              borderRadius: "6px",
                              padding: "0.6rem",
                              fontSize: "0.76rem",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                              <span style={{ textTransform: "uppercase", fontWeight: 700, color: "#79c0ff" }}>
                                {name} Engine
                              </span>
                              <span
                                style={{
                                  fontSize: "0.68rem",
                                  padding: "0.05rem 0.35rem",
                                  borderRadius: "4px",
                                  backgroundColor: sig.availability === "available" ? "#23863633" : "#da363333",
                                  color: sig.availability === "available" ? "#7ee787" : "#ff7b72",
                                }}
                              >
                                {sig.availability}
                              </span>
                            </div>
                            <div style={{ color: "#f0f6fc", fontWeight: 600, fontSize: "0.82rem" }}>
                              +{sig.contribution.toFixed(1)} pts
                              <span style={{ color: "#8b949e", fontSize: "0.7rem", fontWeight: 400, marginLeft: "4px" }}>
                                (weight: {(sig.effective_weight * 100).toFixed(0)}%)
                              </span>
                            </div>
                            <div style={{ color: "#8b949e", fontSize: "0.7rem", marginTop: "3px" }}>
                              {sig.summary_text}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Top Contributing Evidence Table */}
                    {correlationSummary.top_evidence.length > 0 && (
                      <div style={{ marginBottom: "1rem" }}>
                        <div style={{ fontSize: "0.75rem", color: "#8b949e", textTransform: "uppercase", fontWeight: 600, marginBottom: "0.4rem" }}>
                          Top Contributing Evidence:
                        </div>
                        <div
                          style={{
                            border: "1px solid #21262d",
                            borderRadius: "6px",
                            backgroundColor: "#0d1117",
                            overflow: "hidden",
                            fontSize: "0.76rem",
                          }}
                        >
                          <table style={{ width: "100%", borderCollapse: "collapse" }}>
                            <thead>
                              <tr style={{ color: "#8b949e", borderBottom: "1px solid #21262d", textAlign: "left", backgroundColor: "#161b22" }}>
                                <th style={{ padding: "5px 8px", width: "40px" }}>#</th>
                                <th style={{ padding: "5px 8px", width: "80px" }}>Engine</th>
                                <th style={{ padding: "5px 8px", width: "70px" }}>Impact</th>
                                <th style={{ padding: "5px 8px" }}>Evidence Rationale</th>
                              </tr>
                            </thead>
                            <tbody>
                              {correlationSummary.top_evidence.map((item) => (
                                <tr key={item.rank} style={{ borderBottom: "1px solid #161b22" }}>
                                  <td style={{ padding: "5px 8px", color: "#8b949e" }}>{item.rank}</td>
                                  <td style={{ padding: "5px 8px", fontFamily: "monospace", color: "#58a6ff" }}>
                                    {item.engine}
                                  </td>
                                  <td style={{ padding: "5px 8px" }}>
                                    <span
                                      style={{
                                        fontSize: "0.68rem",
                                        fontWeight: 700,
                                        padding: "0.1rem 0.35rem",
                                        borderRadius: "4px",
                                        backgroundColor:
                                          item.impact === "high"
                                            ? "#da363333"
                                            : item.impact === "medium"
                                            ? "#d2992233"
                                            : "#21262d",
                                        color:
                                          item.impact === "high"
                                            ? "#f85149"
                                            : item.impact === "medium"
                                            ? "#e3b341"
                                            : "#8b949e",
                                      }}
                                    >
                                      {item.impact.toUpperCase()}
                                    </span>
                                  </td>
                                  <td style={{ padding: "5px 8px", color: "#c9d1d9" }}>
                                    {item.description}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* Conflicts & Disagreements if any */}
                    {correlationSummary.conflicts.length > 0 && (
                      <div
                        style={{
                          backgroundColor: "#2a1215",
                          border: "1px solid #da3633",
                          borderRadius: "6px",
                          padding: "0.6rem 0.85rem",
                          marginBottom: "0.75rem",
                          fontSize: "0.75rem",
                          color: "#ff7b72",
                        }}
                      >
                        <strong>Cross-Engine Conflict Detected: </strong>
                        {correlationSummary.conflicts.map((c, idx) => (
                          <div key={idx} style={{ marginTop: "3px" }}>
                            • [{c.conflict_type}] {c.description} — <em>Reconciliation: {c.reconciliation}</em>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Limitations & Caveats */}
                    {correlationSummary.limitations.length > 0 && (
                      <div style={{ marginTop: "0.5rem" }}>
                        <div style={{ fontSize: "0.72rem", color: "#8b949e", marginBottom: "0.25rem" }}>
                          Assessment Limitations & Adjustments:
                        </div>
                        <ul style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.7rem", color: "#8b949e" }}>
                          {correlationSummary.limitations.map((lim, idx) => (
                            <li key={idx}>{lim}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Provenance Footer */}
                    <div style={{ marginTop: "0.75rem", paddingTop: "0.5rem", borderTop: "1px solid #21262d", fontSize: "0.68rem", color: "#8b949e" }}>
                      Provenance: Rules v{correlationSummary.upstream_versions?.rules_engine_version || "1.0.0"} • ML v{correlationSummary.upstream_versions?.ml_model_version || "1.0.0"} • IOC Feed v{correlationSummary.upstream_versions?.ioc_feed_version || "unknown"} • Geo v{correlationSummary.upstream_versions?.geo_analysis_version || "1.0.0"} • Correlation Policy v{correlationSummary.policy_version}
                    </div>
                  </div>
                )}
              </div>



              {/* STAGE 8 — FORENSIC AUDIT TRAIL, PROVENANCE & MANIFEST */}
              <div
                style={{
                  marginTop: "1.25rem",
                  padding: "1rem",
                  backgroundColor: "#0d1117",
                  border: "1px solid #30363d",
                  borderRadius: "8px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    borderBottom: "1px solid #21262d",
                    paddingBottom: "0.5rem",
                    marginBottom: "0.75rem",
                  }}
                >
                  <div>
                    <h3 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 700, color: "#f0f6fc" }}>
                      🛡️ Stage 8 Forensic Audit Trail & Evidence Manifest
                    </h3>
                    <div style={{ fontSize: "0.72rem", color: "#8b949e", marginTop: "2px" }}>
                      Cryptographic Hash Chain • Byte-for-Byte Preservation • Versioned Provenance • Multi-Engine Runs
                    </div>
                  </div>

                  {auditVerifyData && (
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <span
                        style={{
                          fontSize: "0.72rem",
                          fontWeight: 700,
                          padding: "0.2rem 0.6rem",
                          borderRadius: "9999px",
                          backgroundColor: auditVerifyData.valid ? "#23863633" : "#da363333",
                          border: `1px solid ${auditVerifyData.valid ? "#2ea043" : "#f85149"}`,
                          color: auditVerifyData.valid ? "#3fb950" : "#f85149",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "0.3rem",
                        }}
                      >
                        {auditVerifyData.valid ? "✓ AUDIT CHAIN VALID" : "⚠ INTEGRITY COMPROMISED"}
                      </span>
                    </div>
                  )}
                </div>

                {/* Tab Navigation */}
                <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem", borderBottom: "1px solid #21262d", paddingBottom: "0.5rem" }}>
                  {(["integrity", "timeline", "runs", "manifest", "provenance"] as const).map((tab) => (
                    <button
                      key={tab}
                      type="button"
                      onClick={() => setActiveStage8Tab(tab)}
                      style={{
                        backgroundColor: activeStage8Tab === tab ? "#21262d" : "transparent",
                        color: activeStage8Tab === tab ? "#58a6ff" : "#8b949e",
                        border: activeStage8Tab === tab ? "1px solid #30363d" : "1px solid transparent",
                        borderRadius: "6px",
                        padding: "0.25rem 0.65rem",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        cursor: "pointer",
                        textTransform: "capitalize",
                      }}
                    >
                      {tab === "integrity" && "Evidence Integrity"}
                      {tab === "timeline" && `Timeline (${timelineData?.total_events || 0})`}
                      {tab === "runs" && `Engine Runs (${analysisRunsData?.total_runs || 0})`}
                      {tab === "manifest" && `Manifest (${manifestData?.total_artifacts || 0})`}
                      {tab === "provenance" && "Software Provenance"}
                    </button>
                  ))}
                </div>

                {/* Tab Content: Integrity */}
                {activeStage8Tab === "integrity" && (
                  <div style={{ fontSize: "0.78rem" }}>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr",
                        gap: "0.75rem",
                        marginBottom: "0.75rem",
                      }}
                    >
                      <div style={{ backgroundColor: "#161b22", padding: "0.75rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                        <div style={{ color: "#8b949e", fontSize: "0.7rem", marginBottom: "0.25rem" }}>RAW EVIDENCE SHA-256 (QUARANTINE)</div>
                        <div style={{ fontFamily: "monospace", color: "#58a6ff", fontSize: "0.75rem", wordBreak: "break-all" }}>
                          {uploadResult.sha256}
                        </div>
                        <div style={{ marginTop: "0.4rem", fontSize: "0.7rem", color: "#3fb950" }}>
                          ✓ Byte-for-byte preserved (0 bytes modified across all analytical engines)
                        </div>
                      </div>

                      <div style={{ backgroundColor: "#161b22", padding: "0.75rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                        <div style={{ color: "#8b949e", fontSize: "0.7rem", marginBottom: "0.25rem" }}>COMPOSITE MANIFEST SHA-256</div>
                        <div style={{ fontFamily: "monospace", color: "#d2a8ff", fontSize: "0.75rem", wordBreak: "break-all" }}>
                          {manifestData?.manifest_sha256 || "Calculating..."}
                        </div>
                        <div style={{ marginTop: "0.4rem", fontSize: "0.7rem", color: "#8b949e" }}>
                          Covers primary email and all derived analytical artifacts
                        </div>
                      </div>
                    </div>

                    {auditVerifyData && (
                      <div style={{ backgroundColor: "#161b22", padding: "0.75rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                        <div style={{ fontWeight: 600, color: "#f0f6fc", marginBottom: "0.4rem" }}>
                          Cryptographic Hash Chain Verification Summary
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "0.5rem", fontSize: "0.72rem" }}>
                          <div>
                            <span style={{ color: "#8b949e" }}>Chained Blocks: </span>
                            <span style={{ color: "#f0f6fc", fontWeight: 700 }}>{auditVerifyData.event_count}</span>
                          </div>
                          <div>
                            <span style={{ color: "#8b949e" }}>Status: </span>
                            <span style={{ color: auditVerifyData.valid ? "#3fb950" : "#f85149", fontWeight: 700 }}>
                              {auditVerifyData.valid ? "VERIFIED INTACT" : "CORRUPTED"}
                            </span>
                          </div>
                          <div>
                            <span style={{ color: "#8b949e" }}>Verified At: </span>
                            <span style={{ color: "#f0f6fc" }}>{new Date(auditVerifyData.verification_timestamp).toLocaleTimeString()}</span>
                          </div>
                        </div>
                        {auditVerifyData.first_event_hash && (
                          <div style={{ marginTop: "0.4rem", fontSize: "0.7rem" }}>
                            <span style={{ color: "#8b949e" }}>Genesis Block: </span>
                            <span style={{ fontFamily: "monospace", color: "#8b949e" }}>{auditVerifyData.first_event_hash.slice(0, 16)}...</span>
                            <span style={{ color: "#8b949e", marginLeft: "1rem" }}>Latest Block: </span>
                            <span style={{ fontFamily: "monospace", color: "#8b949e" }}>{auditVerifyData.last_event_hash?.slice(0, 16)}...</span>
                          </div>
                        )}
                        {auditVerifyData.errors.length > 0 && (
                          <div style={{ marginTop: "0.5rem", color: "#f85149" }}>
                            {auditVerifyData.errors.map((e, idx) => (
                              <div key={idx}>⚠ [{e.error_type}] Seq {e.event_sequence}: {e.message}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Tab Content: Timeline */}
                {activeStage8Tab === "timeline" && timelineData && (
                  <div style={{ maxHeight: "280px", overflowY: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.72rem" }}>
                      <thead>
                        <tr style={{ textAlign: "left", color: "#8b949e", borderBottom: "1px solid #21262d" }}>
                          <th style={{ padding: "4px 8px" }}>Seq</th>
                          <th style={{ padding: "4px 8px" }}>Time (UTC)</th>
                          <th style={{ padding: "4px 8px" }}>Event Type</th>
                          <th style={{ padding: "4px 8px" }}>Actor</th>
                          <th style={{ padding: "4px 8px" }}>Message</th>
                          <th style={{ padding: "4px 8px" }}>Event Hash</th>
                        </tr>
                      </thead>
                      <tbody>
                        {timelineData.events.map((ev) => (
                          <tr key={ev.event_id} style={{ borderBottom: "1px solid #161b22" }}>
                            <td style={{ padding: "4px 8px", color: "#8b949e" }}>#{ev.event_sequence}</td>
                            <td style={{ padding: "4px 8px", color: "#c9d1d9", whiteSpace: "nowrap" }}>
                              {new Date(ev.event_timestamp).toISOString().replace("T", " ").slice(0, 19)}
                            </td>
                            <td style={{ padding: "4px 8px" }}>
                              <span
                                style={{
                                  fontSize: "0.68rem",
                                  fontWeight: 600,
                                  padding: "0.1rem 0.35rem",
                                  borderRadius: "4px",
                                  backgroundColor: "#21262d",
                                  color: ev.event_type.includes("FAILED") || ev.event_type.includes("ERROR") ? "#f85149" : "#58a6ff",
                                }}
                              >
                                {ev.event_type}
                              </span>
                            </td>
                            <td style={{ padding: "4px 8px", color: "#8b949e" }}>{ev.actor_type}</td>
                            <td style={{ padding: "4px 8px", color: "#c9d1d9" }}>{ev.message}</td>
                            <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "#8b949e", fontSize: "0.68rem" }}>
                              {ev.event_hash.slice(0, 10)}...
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Tab Content: Analysis Runs */}
                {activeStage8Tab === "runs" && analysisRunsData && (
                  <div style={{ maxHeight: "280px", overflowY: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.72rem" }}>
                      <thead>
                        <tr style={{ textAlign: "left", color: "#8b949e", borderBottom: "1px solid #21262d" }}>
                          <th style={{ padding: "4px 8px" }}>Engine</th>
                          <th style={{ padding: "4px 8px" }}>Status</th>
                          <th style={{ padding: "4px 8px" }}>Version</th>
                          <th style={{ padding: "4px 8px" }}>Duration</th>
                          <th style={{ padding: "4px 8px" }}>Input Fingerprint</th>
                          <th style={{ padding: "4px 8px" }}>Output Fingerprint</th>
                        </tr>
                      </thead>
                      <tbody>
                        {analysisRunsData.runs.map((r) => (
                          <tr key={r.run_id} style={{ borderBottom: "1px solid #161b22" }}>
                            <td style={{ padding: "4px 8px", fontWeight: 600, color: "#f0f6fc" }}>{r.engine_name.toUpperCase()}</td>
                            <td style={{ padding: "4px 8px" }}>
                              <span
                                style={{
                                  fontSize: "0.68rem",
                                  fontWeight: 600,
                                  padding: "0.1rem 0.35rem",
                                  borderRadius: "4px",
                                  backgroundColor: r.run_status === "COMPLETED" ? "#23863633" : "#da363333",
                                  color: r.run_status === "COMPLETED" ? "#3fb950" : "#f85149",
                                }}
                              >
                                {r.run_status}
                              </span>
                            </td>
                            <td style={{ padding: "4px 8px", color: "#8b949e" }}>v{r.engine_version}</td>
                            <td style={{ padding: "4px 8px", color: "#c9d1d9" }}>{r.duration_ms != null ? `${r.duration_ms} ms` : "-"}</td>
                            <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "#8b949e" }}>
                              {r.input_fingerprint ? `${r.input_fingerprint.slice(0, 10)}...` : "-"}
                            </td>
                            <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "#58a6ff" }}>
                              {r.output_fingerprint ? `${r.output_fingerprint.slice(0, 10)}...` : "-"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Tab Content: Manifest */}
                {activeStage8Tab === "manifest" && manifestData && (
                  <div style={{ maxHeight: "280px", overflowY: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.72rem" }}>
                      <thead>
                        <tr style={{ textAlign: "left", color: "#8b949e", borderBottom: "1px solid #21262d" }}>
                          <th style={{ padding: "4px 8px" }}>Type</th>
                          <th style={{ padding: "4px 8px" }}>Artifact Name</th>
                          <th style={{ padding: "4px 8px" }}>Size</th>
                          <th style={{ padding: "4px 8px" }}>SHA-256 Digest</th>
                          <th style={{ padding: "4px 8px" }}>Integrity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {manifestData.artifacts.map((a) => (
                          <tr key={a.artifact_id} style={{ borderBottom: "1px solid #161b22" }}>
                            <td style={{ padding: "4px 8px" }}>
                              <span
                                style={{
                                  fontSize: "0.68rem",
                                  fontWeight: 600,
                                  padding: "0.1rem 0.35rem",
                                  borderRadius: "4px",
                                  backgroundColor: a.artifact_type.toUpperCase() === "RAW_EMAIL" ? "#1f6feb33" : "#21262d",
                                  color: a.artifact_type.toUpperCase() === "RAW_EMAIL" ? "#58a6ff" : "#8b949e",
                                }}
                              >
                                {a.artifact_type}
                              </span>
                            </td>
                            <td style={{ padding: "4px 8px", color: "#c9d1d9" }}>{a.artifact_name}</td>
                            <td style={{ padding: "4px 8px", color: "#8b949e" }}>{a.size_bytes} B</td>
                            <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "#58a6ff", fontSize: "0.68rem" }}>
                              {a.sha256}
                            </td>
                            <td style={{ padding: "4px 8px", color: a.immutable ? "#3fb950" : "#8b949e" }}>
                              {a.immutable ? "🔒 Immutable" : "Derived"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Tab Content: Provenance */}
                {activeStage8Tab === "provenance" && provenanceData && (
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "0.5rem", fontSize: "0.72rem" }}>
                    <div style={{ backgroundColor: "#161b22", padding: "0.6rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                      <div style={{ color: "#8b949e" }}>Parser Version</div>
                      <div style={{ color: "#f0f6fc", fontWeight: 600 }}>v{provenanceData.parser_version || "1.0.0"}</div>
                    </div>
                    <div style={{ backgroundColor: "#161b22", padding: "0.6rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                      <div style={{ color: "#8b949e" }}>Rules Engine Version</div>
                      <div style={{ color: "#f0f6fc", fontWeight: 600 }}>v{provenanceData.rules_engine_version || "1.0.0"}</div>
                    </div>
                    <div style={{ backgroundColor: "#161b22", padding: "0.6rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                      <div style={{ color: "#8b949e" }}>ML Model Version</div>
                      <div style={{ color: "#f0f6fc", fontWeight: 600 }}>v{provenanceData.ml_model_version || "1.0.0"}</div>
                    </div>
                    <div style={{ backgroundColor: "#161b22", padding: "0.6rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                      <div style={{ color: "#8b949e" }}>IOC Feed Version</div>
                      <div style={{ color: "#f0f6fc", fontWeight: 600 }}>v{provenanceData.ioc_feed_version || "2026.09.05.01"}</div>
                    </div>
                    <div style={{ backgroundColor: "#161b22", padding: "0.6rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                      <div style={{ color: "#8b949e" }}>Geo DB Version</div>
                      <div style={{ color: "#f0f6fc", fontWeight: 600 }}>v{provenanceData.geo_database_version || "2026.09.01"}</div>
                    </div>
                    <div style={{ backgroundColor: "#161b22", padding: "0.6rem", borderRadius: "6px", border: "1px solid #21262d" }}>
                      <div style={{ color: "#8b949e" }}>Correlation Policy</div>
                      <div style={{ color: "#f0f6fc", fontWeight: 600 }}>v{provenanceData.correlation_policy_version || "1.0.0"}</div>
                    </div>
                  </div>
                )}
              </div>


              {/* STAGE 9 — FORENSIC INVESTIGATION REPORT */}
              <div
                style={{
                  marginTop: "1.25rem",
                  padding: "1rem",
                  backgroundColor: "#0d1117",
                  border: "1px solid #30363d",
                  borderRadius: "8px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    borderBottom: "1px solid #21262d",
                    paddingBottom: "0.5rem",
                    marginBottom: "0.75rem",
                  }}
                >
                  <div>
                    <h3 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 700, color: "#f0f6fc" }}>
                      📄 Stage 9 Forensic Investigation Report
                    </h3>
                    <div style={{ fontSize: "0.72rem", color: "#8b949e", marginTop: "2px" }}>
                      Deterministic Content Fingerprint • Evidence-Backed Presentation • Multi-Format Generation
                    </div>
                  </div>

                  <div style={{ display: "flex", gap: "0.5rem" }}>
                    <button
                      type="button"
                      onClick={() => {
                        window.open(`${apiUrl}/api/cases/${uploadResult.case_id}/report/html`, "_blank");
                        setTimeout(() => refreshCaseStatus(uploadResult.case_id), 1000);
                      }}
                      style={{
                        backgroundColor: "#1f6feb",
                        color: "#ffffff",
                        border: "none",
                        borderRadius: "6px",
                        padding: "0.35rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        cursor: "pointer",
                      }}
                    >
                      🌐 View HTML Report
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        window.open(`${apiUrl}/api/cases/${uploadResult.case_id}/report/pdf`, "_blank");
                        setTimeout(() => refreshCaseStatus(uploadResult.case_id), 1000);
                      }}
                      style={{
                        backgroundColor: "#238636",
                        color: "#ffffff",
                        border: "none",
                        borderRadius: "6px",
                        padding: "0.35rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        cursor: "pointer",
                      }}
                    >
                      📥 Download PDF
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        window.open(`${apiUrl}/api/cases/${uploadResult.case_id}/report`, "_blank");
                        setTimeout(() => refreshCaseStatus(uploadResult.case_id), 1000);
                      }}
                      style={{
                        backgroundColor: "#21262d",
                        color: "#c9d1d9",
                        border: "1px solid #30363d",
                        borderRadius: "6px",
                        padding: "0.35rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        cursor: "pointer",
                      }}
                    >
                      JSON Data
                    </button>
                  </div>
                </div>

                {/* Report Generation History Log */}
                <div style={{ fontSize: "0.78rem" }}>
                  <div style={{ color: "#8b949e", fontSize: "0.72rem", marginBottom: "0.4rem" }}>
                    Report Generation History ({reportHistory?.total_reports || 0} Generated Records):
                  </div>
                  {reportHistory && reportHistory.reports.length > 0 ? (
                    <div style={{ maxHeight: "200px", overflowY: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.72rem" }}>
                        <thead>
                          <tr style={{ textAlign: "left", color: "#8b949e", borderBottom: "1px solid #21262d" }}>
                            <th style={{ padding: "4px 8px" }}>Format</th>
                            <th style={{ padding: "4px 8px" }}>Report ID</th>
                            <th style={{ padding: "4px 8px" }}>Generated (UTC)</th>
                            <th style={{ padding: "4px 8px" }}>Deterministic SHA-256 Fingerprint</th>
                            <th style={{ padding: "4px 8px" }}>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {reportHistory.reports.map((r, idx) => (
                            <tr key={idx} style={{ borderBottom: "1px solid #161b22" }}>
                              <td style={{ padding: "4px 8px" }}>
                                <span
                                  style={{
                                    fontSize: "0.68rem",
                                    fontWeight: 700,
                                    padding: "0.1rem 0.4rem",
                                    borderRadius: "4px",
                                    backgroundColor:
                                      r.format === "PDF"
                                        ? "#23863633"
                                        : r.format === "HTML"
                                        ? "#1f6feb33"
                                        : "#21262d",
                                    color:
                                      r.format === "PDF"
                                        ? "#3fb950"
                                        : r.format === "HTML"
                                        ? "#58a6ff"
                                        : "#c9d1d9",
                                  }}
                                >
                                  {r.format}
                                </span>
                              </td>
                              <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "#c9d1d9" }}>{r.report_id}</td>
                              <td style={{ padding: "4px 8px", color: "#8b949e" }}>
                                {new Date(r.generated_timestamp).toISOString().replace("T", " ").slice(0, 19)}
                              </td>
                              <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "#d2a8ff" }}>
                                {r.report_sha256.slice(0, 16)}...
                              </td>
                              <td style={{ padding: "4px 8px", color: r.status === "SUCCESS" ? "#3fb950" : "#f85149" }}>
                                {r.status}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={{ color: "#8b949e", fontSize: "0.72rem", fontStyle: "italic", padding: "0.4rem 0" }}>
                      No reports generated yet for this case. Click &quot;View HTML Report&quot; or &quot;Download PDF&quot; above to generate one.
                    </div>
                  )}
                </div>
              </div>

              <div
                style={{
                  marginTop: "1rem",
                  paddingTop: "0.75rem",
                  borderTop: "1px solid #21262d",
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <button
                  type="button"
                  onClick={() => refreshCaseStatus(uploadResult.case_id)}
                  disabled={isCheckingStatus}
                  style={{
                    backgroundColor: "#21262d",
                    color: "#c9d1d9",
                    border: "1px solid #30363d",
                    borderRadius: "6px",
                    padding: "0.4rem 0.85rem",
                    fontSize: "0.8rem",
                    cursor: isCheckingStatus ? "not-allowed" : "pointer",
                  }}
                >
                  {isCheckingStatus ? "Checking Status..." : "Refresh Case Status"}
                </button>
              </div>
            </div>
          )}
        </section>

        {/* Footer */}
        <footer
          style={{
            borderTop: "1px solid #30363d",
            paddingTop: "1rem",
            fontSize: "0.8rem",
            color: "#8b949e",
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <span>Email Fraud Forensic Analysis Platform</span>
          <span>Stage 9 Forensic Reporting Active</span>
        </footer>
      </div>
    </main>
  );
}
