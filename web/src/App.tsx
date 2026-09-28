import { useEffect, useMemo, useRef, useState } from "react";
import { HeroTopology } from "./HeroTopology";
import { IncidentConclusion, type IncidentConclusionData } from "./IncidentConclusion";
import { ReplayEvidence } from "./ReplayEvidence";
import { OverallRisk, type OverallRiskData } from "./OverallRisk";
import { AnalystRoute } from "./AnalystRoute";
import { apiErrorMessage } from "./apiError";
import {
  Activity, ArrowRight, BarChart3, Check, ChevronRight, CircleAlert, Download, Eye,
  FileJson, FileUp, Filter, Moon, Network, Radio, RefreshCw, Search, Sun, X,
} from "lucide-react";

type Theme = "dark" | "light";
const THEME_KEY = "drastha-theme";
type Route = "workbench" | "analyst";
const routeFromPath = (): Route => window.location.pathname.replace(/\/$/, "") === "/analyst" ? "analyst" : "workbench";

function initialTheme(): Theme {
  try {
    const saved = window.localStorage.getItem(THEME_KEY);
    if (saved === "dark" || saved === "light") return saved;
    return "light";
  } catch {
    return "light";
  }
}

type Evidence = { name: string; observed: number | string; comparison: string; explanation: string };
type Alert = {
  alert_id: string; detector_id: string; detector_version?: string; threat_type: string; threat_class?: string; subtype: string;
  severity: string; confidence: number; window_start: number; window_end: number;
  src_ip: string; dst_ip?: string; flow_ids?: string[]; evidence: Evidence[]; limitations: string[];
};
type Feedback = { feedback_id: string; disposition: string; analyst: string; timestamp: number; notes: string };
type Incident = {
  incident_id: string; src_ip: string; first_seen: number; last_seen: number;
  alert_ids: string[]; detector_ids: string[]; threat_types: string[];
  confidence: number; risk_score: number; severity: string; status: string;
  scoring_factors: Evidence[]; conclusion?: IncidentConclusionData | null; alerts?: Alert[]; feedback?: Feedback[];
};
type Metrics = { total_incidents: number; active_incidents: number; critical_incidents: number; feedback_records: number; average_risk_score: number };
type DemoStage = { name: string; status: string; detail: string; duration_ms?: number; records?: number; rejected?: number; alerts?: number; incidents?: number };
type DemoRun = { status: string; telemetry_status: string; elapsed_ms?: number; stages: DemoStage[]; run_id?: string };
type Health = { status: string; mode: string; storage: string; return_path_required: boolean; demo_run?: DemoRun | null };
type FeatureCoverage = { mode: string; counts: Record<string, number>; network_direction_status: string; exfiltration_direction: string };

function FeatureCoverageNote({ value }: { value?: FeatureCoverage }) {
  if (!value) return null;
  return <p className="scope-note"><b>Encrypted-session feature coverage ({value.mode}):</b> {value.counts.derived ?? 0} measured, {value.counts.supplied_compatibility ?? 0} supplied demo scores, {value.counts.insufficient_evidence ?? 0} insufficient evidence (including baseline warm-up). Missing evidence does not mean benign. <b>Network boundary:</b> {value.network_direction_status}; exfiltration uses {value.exfiltration_direction}.</p>;
}
export type UploadResult = {
  run_id: string;
  analysed_at?: number; capture_start?: number | null; capture_end?: number | null;
  verdict: string; headline: string; summary: string; filename: string; file_size_bytes: number;
  analysis_ms: number; quality: {
    status: string; records_received: number; records_accepted: number; records_rejected: number;
    records_quarantined: number; out_of_order_records: number; duplicate_uid_count: number;
    invalid_timestamp_count: number; unsupported_record_count: number;
    degraded_reasons: string[]; errors: string[];
  };
  feature_coverage?: FeatureCoverage;
  alerts: Alert[]; incidents: Incident[]; top_incident_id?: string; stages: DemoStage[]; scope_note: string;
  overall_risk?: OverallRiskData;
  telemetry?: { connection_records: number; dns_records: number; encrypted_session_records: number; supplied_labels_ignored: boolean };
  context_policy?: {
    source: string; trusted_periodic_rules: number; approved_bulk_transfer_rules: number;
    authorized_scanner_sources?: number; suppressed_connection_evaluations: number;
    suppressed_by_detector?: Record<string, number>;
  };
  evaluation?: { true_positive: number; false_positive: number; false_negative: number; true_negative: number; precision: number; recall: number; f1_score: number; false_positive_rate: number } | null;
};
export type RunEvidence = {
  run_id: string; filename?: string; quality?: { status: string };
  analysed_at?: number | null; capture_start?: number | null; capture_end?: number | null;
  alerts: Alert[]; incidents: Incident[]; overall_risk?: OverallRiskData;
};
export type RunSummary = {
  run_id: string; filename: string; source: string; analysed_at: number | null;
  capture_start: number | null; capture_end: number | null;
  quality_status: string; findings: number; incidents: number;
};
type RunHistory = { items: RunSummary[]; total: number; has_more: boolean };
type StreamRecord = {
  timestamp: number; flow_id: string; src_ip: string; dst_ip: string; protocol: string;
  dst_port: number; outbound_bytes: number; inbound_bytes: number; record_kind?: string; query?: string;
};
type StreamFinding = { alert: Alert; detection_method: string; incident: Incident };
type StreamState = {
  status: "running" | "complete" | "error"; processed: number; total: number;
  latest?: StreamRecord; findings: StreamFinding[]; topIncidentId?: string;
  riskScore: number; elapsedMs?: number;
  featureCoverage?: FeatureCoverage;
};

const API = "/api";
const PIPELINE_TEMPLATE: DemoStage[] = [
  { name: "Read traffic", status: "ready", detail: "Accept one-way network records" },
  { name: "Check data", status: "ready", detail: "Reject incomplete or damaged records" },
  { name: "Find behaviour", status: "ready", detail: "Look for suspicious network patterns" },
  { name: "Connect findings", status: "ready", detail: "Join related activity into one story" },
  { name: "Show result", status: "ready", detail: "Store evidence for analyst review" },
];
const LABELS: Record<string, string> = {
  command_and_control: "Command-and-control behaviour", data_exfiltration: "Possible data exfiltration",
  reconnaissance: "Network reconnaissance", denial_of_service: "Volumetric DDoS",
  dns_threat: "Suspicious DNS behaviour", encrypted_session_threat: "Suspicious encrypted-session behaviour",
  periodic_beacon: "Repeated callback pattern", outbound_volume_anomaly: "Unusual outbound data transfer",
  dga_like_domain: "Algorithmically generated domain pattern", dns_tunnelling: "Possible DNS tunnelling",
  encrypted_session_metadata_anomaly: "Encrypted-session metadata anomaly",
  vertical_port_scan: "Many ports checked on one device", horizontal_host_scan: "One service checked across many devices",
  multi_host_port_scan: "Multi-host/port reconnaissance",
  syn_flood: "Many incomplete connections to one service", udp_flood: "Unusually high UDP traffic",
  distributed_source_syn_flood: "Distributed-source SYN flood",
  udp_reflection_amplification: "UDP reflection or amplification pattern",
  dominant_incident_risk: "Dominant incident",
  incident_breadth_bonus: "Incident breadth",
  threat_diversity_bonus: "Threat diversity",
  target_port_concentration: "Traffic focused on one service", distinct_suspicious_domains: "Generated-looking domains",
  model_probability: "ML model score", queried_domain: "Domain checked by the model",
  txt_query_ratio: "TXT-query share", fingerprint_prevalence: "Fingerprint prevalence",
  packet_size_sequence_anomaly: "Packet-size anomaly", timing_sequence_anomaly: "Timing anomaly",
  outbound_to_inbound_ratio: "Outbound-to-inbound ratio", related_findings_merged: "Repeated findings merged",
};

function ReplayOutcomeStatus({ result }: { result: UploadResult }) {
  const insufficient = result.feature_coverage?.counts.insufficient_evidence ?? 0;
  const suppressed = result.context_policy?.suppressed_connection_evaluations ?? 0;
  const breakdown = result.context_policy?.suppressed_by_detector;
  return <div className="analysis-status-grid" aria-label="Replay outcome categories">
    <article className="outcome-detected"><span>Detected threat</span><b>{result.alerts.length} findings</b>
      <small>Behaviour crossed a detector threshold and was correlated for review.</small></article>
    <article className="outcome-suppressed"><span>Approved context</span><b>{suppressed} records suppressed</b>
      <small>{breakdown ? `${breakdown.command_and_control ?? 0} C2 · ${breakdown.data_exfiltration ?? 0} exfiltration · ${breakdown.reconnaissance ?? 0} recon` : "Matched operator-controlled policy; retained as an auditable count."}</small></article>
    <article className="outcome-insufficient"><span>Insufficient evidence</span><b>{insufficient} encrypted sessions</b>
      <small>Not classified as benign or malicious; more passive baseline evidence is required.</small></article>
    <article className="outcome-rejected"><span>Invalid / rejected input</span><b>{result.quality.records_rejected} records</b>
      <small>Quarantined by strict schema, timestamp and quality validation.</small></article>
  </div>;
}
const label = (value: string) => LABELS[value] || value.replaceAll("_", " ");
const timeLabel = (value: number, origin?: number) => value < 946684800
  ? origin === undefined ? `Capture +${Math.round(value)}s` : `+${Math.max(0, Math.round(value - origin))}s`
  : new Date(value * 1000).toLocaleString([], { year: "numeric", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, { headers: { "Content-Type": "application/json", ...options?.headers }, ...options });
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    throw new Error(apiErrorMessage(body, response.status));
  }
  return response.json();
}

function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [route, setRoute] = useState<Route>(routeFromPath);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [queueDetails, setQueueDetails] = useState<Incident[]>([]);
  const [queueDetailsLoading, setQueueDetailsLoading] = useState(false);
  const [runHistory, setRunHistory] = useState<RunSummary[]>([]);
  const [runHistoryHasMore, setRunHistoryHasMore] = useState(false);
  const [runHistoryLoading, setRunHistoryLoading] = useState(true);
  const [latestRun, setLatestRun] = useState<RunEvidence | null>(null);
  const [analystRunId, setAnalystRunId] = useState<string | null>(null);
  const [analystRun, setAnalystRun] = useState<RunEvidence | null>(null);
  const [showAllQueue, setShowAllQueue] = useState(false);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [evidenceRun, setEvidenceRun] = useState<{ run: RunEvidence; incidentId?: string } | null>(null);
  const detailRequest = useRef(0);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [analyst, setAnalyst] = useState("demo-analyst");
  const [notes, setNotes] = useState("");
  const [demoRun, setDemoRun] = useState<DemoRun | null>(null);
  const [running, setRunning] = useState(false);
  const [visibleStages, setVisibleStages] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<UploadResult | null>(null);
  const [dragging, setDragging] = useState(false);
  const [stream, setStream] = useState<StreamState | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const eventSource = useRef<EventSource | null>(null);
  const historyRequest = useRef(0);
  const runSelectionRequest = useRef(0);
  const historySelectionTouched = useRef(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "light" ? "#f4f8fb" : "#07131f");
    try { window.localStorage.setItem(THEME_KEY, theme); } catch { /* Private browsing may disable storage. */ }
  }, [theme]);

  useEffect(() => {
    const onPopState = () => { setRoute(routeFromPath()); detailRequest.current += 1; setSelected(null); setEvidenceRun(null); };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const refresh = async (keepSelection = true) => {
    setLoading(true);
    try {
      const [queue, summary, service] = await Promise.all([api<Incident[]>("/incidents"), api<Metrics>("/metrics"), api<Health>("/health")]);
      setIncidents(queue); setMetrics(summary); setHealth(service);
      if (service.demo_run) { setDemoRun(service.demo_run); setVisibleStages(service.demo_run.stages.length); }
      if (keepSelection && selected) await openIncident(selected.incident_id);
    } catch (error) { setMessage((error as Error).message); }
    finally { setLoading(false); }
  };
  const loadRunHistory = async (preferred?: RunEvidence) => {
    const request = ++historyRequest.current;
    setRunHistoryLoading(true);
    try {
      const page = await api<RunHistory>("/analysis-runs?limit=100");
      if (request !== historyRequest.current) return;
      setRunHistory(page.items); setRunHistoryHasMore(page.has_more);
      if (preferred) {
        historySelectionTouched.current = false;
        setLatestRun(preferred); setAnalystRunId(preferred.run_id); setAnalystRun(preferred);
        setShowAllQueue(false);
      } else {
        // Legacy snapshots have capture times but no recorded analysis time.
        // Do not guess which one was analysed most recently.
        const newest = page.items.find((item) => item.analysed_at !== null);
        if (newest) {
          const report = await api<RunEvidence>(`/analysis-runs/${newest.run_id}`);
          if (request !== historyRequest.current) return;
          setLatestRun(report);
          if (!historySelectionTouched.current) { setAnalystRunId(report.run_id); setAnalystRun(report); }
        }
      }
    } catch (error) { if (request === historyRequest.current) setMessage(`Run history could not load: ${(error as Error).message}`); }
    finally { if (request === historyRequest.current) setRunHistoryLoading(false); }
  };
  const loadOlderRuns = async () => {
    if (!runHistoryHasMore || runHistoryLoading) return;
    setRunHistoryLoading(true);
    try {
      const page = await api<RunHistory>(`/analysis-runs?limit=100&offset=${runHistory.length}`);
      setRunHistory((current) => [...current, ...page.items]); setRunHistoryHasMore(page.has_more);
    } catch (error) { setMessage(`Older runs could not load: ${(error as Error).message}`); }
    finally { setRunHistoryLoading(false); }
  };
  const selectAnalystRun = async (runId: string | null) => {
    const request = ++runSelectionRequest.current;
    historySelectionTouched.current = true;
    setAnalystRunId(runId); setAnalystRun(null);
    if (!runId) return;
    if (latestRun?.run_id === runId) { setAnalystRun(latestRun); return; }
    setRunHistoryLoading(true);
    try {
      const report = await api<RunEvidence>(`/analysis-runs/${runId}`);
      if (request === runSelectionRequest.current) setAnalystRun(report);
    } catch (error) { if (request === runSelectionRequest.current) setMessage(`Saved run could not load: ${(error as Error).message}`); }
    finally { if (request === runSelectionRequest.current) setRunHistoryLoading(false); }
  };
  useEffect(() => {
    void refresh(false);
    void loadRunHistory();
    return () => { eventSource.current?.close(); detailRequest.current += 1; };
  }, []);

  useEffect(() => {
    if (route !== "analyst" || analystRunId || stream?.status === "running" || loading) return;
    let cancelled = false;
    setQueueDetails([]);
    if (!incidents.length) { setQueueDetailsLoading(false); return; }
    setQueueDetailsLoading(true);
    const loadDetails = async () => {
      const details: Incident[] = [];
      for (let index = 0; index < incidents.length; index += 8) {
        const batch = await Promise.all(incidents.slice(index, index + 8).map((item) => api<Incident>(`/incidents/${item.incident_id}`)));
        if (cancelled) return;
        details.push(...batch);
      }
      if (!cancelled) { setQueueDetails(details); setQueueDetailsLoading(false); }
    };
    void loadDetails().catch((error) => { if (!cancelled) { setQueueDetailsLoading(false); setMessage(`Analyst evidence could not load: ${(error as Error).message}`); } });
    return () => { cancelled = true; };
  }, [route, incidents, analystRunId, stream?.status, loading]);

  const queueItems = latestRun && !showAllQueue ? latestRun.incidents : incidents;
  const filtered = useMemo(() => queueItems.filter((item) => {
    const text = `${item.src_ip} ${item.incident_id} ${item.threat_types.join(" ")}`.toLowerCase();
    return text.includes(query.toLowerCase()) && (severity === "all" || item.severity === severity);
  }), [queueItems, query, severity]);
  const openIncident = async (id: string, expectedAlertIds?: string[], snapshot?: RunEvidence) => {
    const request = ++detailRequest.current;
    setSelected(null); setEvidenceRun(null); setNotes("");
    try {
      const incident = await api<Incident>(`/incidents/${id}`);
      if (request !== detailRequest.current) return;
      if (expectedAlertIds && [...incident.alert_ids].sort().join("|") !== [...expectedAlertIds].sort().join("|")) {
        if (snapshot) openReplayEvidence(snapshot, id);
        else setMessage("Saved incident membership changed; review the original run snapshot.");
      } else setSelected(incident);
    } catch (error) { if (request === detailRequest.current) setMessage((error as Error).message); }
  };
  const closeEvidence = () => {
    detailRequest.current += 1; setSelected(null); setEvidenceRun(null); setNotes("");
  };
  const navigate = (destination: Route, anchor?: string) => {
    const path = destination === "analyst" ? "/analyst" : `/${anchor ? `#${anchor}` : ""}`;
    window.history.pushState(null, "", path);
    closeEvidence(); setRoute(destination);
    window.requestAnimationFrame(() => anchor ? document.getElementById(anchor)?.scrollIntoView() : window.scrollTo(0, 0));
  };
  const openReplayEvidence = (run: RunEvidence, incidentId?: string) => {
    closeEvidence(); setEvidenceRun({ run, incidentId });
  };
  const revealStages = async (stages: DemoStage[]) => {
    setVisibleStages(0);
    for (let index = 1; index <= stages.length; index += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 180)); setVisibleStages(index);
    }
  };
  const runDemo = async () => {
    if (running || uploading || stream?.status === "running") return;
    closeEvidence(); setStream(null);
    setRunning(true); setUploadResult(null); setMessage("Running the known attack replay…");
    try {
      const result = await api<DemoRun>("/demo/run", { method: "POST" });
      setDemoRun(result); await revealStages(result.stages); await refresh(false);
      if (result.run_id) {
        const report = await api<RunEvidence>(`/analysis-runs/${result.run_id}`);
        setLatestRun(report); setAnalystRunId(report.run_id); setAnalystRun(report); setShowAllQueue(false);
        void loadRunHistory(report);
      }
      setMessage(`Replay complete. A critical incident was created in ${result.elapsed_ms ?? "—"} ms.`);
    } catch (error) { setMessage((error as Error).message); }
    finally { setRunning(false); }
  };
  const startLiveStream = () => {
    if (running || uploading || stream?.status === "running") return;
    closeEvidence();
    eventSource.current?.close();
    setAnalystRunId(null); setAnalystRun(null);
    setUploadResult(null); setStream({ status: "running", processed: 0, total: 0, findings: [], riskScore: 0 });
    setMessage("Listening to the simulated one-way IP stream…");
    let finished = false;
    const source = new EventSource(`${API}/stream/simulated`);
    eventSource.current = source;
    source.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "started") {
        setStream((current) => current ? { ...current, total: data.total_records } : current);
      } else if (data.type === "traffic") {
        setStream((current) => current ? { ...current, processed: data.processed, total: data.total_records, latest: data.record } : current);
      } else if (data.type === "alert") {
        setStream((current) => current ? {
          ...current, processed: data.processed,
          findings: [...current.findings, { alert: data.alert, detection_method: data.detection_method, incident: data.incident }],
          topIncidentId: data.incident.incident_id,
          riskScore: Math.max(current.riskScore, data.incident.risk_score),
        } : current);
      } else if (data.type === "complete") {
        finished = true; source.close();
        setStream((current) => current ? { ...current, status: "complete", findings: data.findings ?? current.findings, processed: data.processed, total: data.total_records, topIncidentId: data.top_incident_id, riskScore: data.risk_score, elapsedMs: data.elapsed_ms, featureCoverage: data.feature_coverage } : current);
        setDemoRun({ status: "completed", telemetry_status: data.quality?.status ?? "unavailable", elapsed_ms: data.elapsed_ms, stages: [
          { name: "Receive stream", status: "completed", detail: "Accepted passive IP records", records: data.processed },
          { name: "Check data", status: data.quality?.status ?? "unavailable", detail: "Validated incoming records in source order", records: data.processed },
          { name: "Detect and classify", status: data.alerts ? "detected" : "no_alert", detail: "Ran behavioural and ML-capable detection paths", alerts: data.alerts },
          { name: "Score intelligence", status: data.risk_score >= 80 ? "critical" : "completed", detail: "Correlated evidence and calculated priority", incidents: data.incidents },
          { name: "Update dashboard", status: "ready", detail: "Published labelled intelligence for review", incidents: data.incidents },
        ] });
        setVisibleStages(5);
        void Promise.all([api<Incident[]>("/incidents"), api<Metrics>("/metrics")]).then(([queue, summary]) => { setIncidents(queue); setMetrics(summary); });
        setMessage(`Live analysis complete: ${data.alerts} labelled findings, risk ${data.risk_score}/100.`);
        if (data.run_id) {
          setAnalystRunId(data.run_id); setAnalystRun(null);
          void api<RunEvidence>(`/analysis-runs/${data.run_id}`).then((report) => {
            setLatestRun(report); setAnalystRun(report); setShowAllQueue(false);
            void loadRunHistory(report);
          }).catch((error) => setMessage(`Stream saved, but its history could not load: ${(error as Error).message}`));
        }
      }
    };
    source.onerror = () => {
      source.close();
      if (!finished) { setStream((current) => current ? { ...current, status: "error" } : current); setMessage("The live stream stopped before analysis completed."); }
    };
  };
  const analyseFile = async (file?: File) => {
    if (running || uploading || stream?.status === "running") return;
    if (!file) return;
    if (file.size > 5_000_000) { setMessage("Choose a replay smaller than 5 MB."); return; }
    closeEvidence(); setStream(null);
    setUploading(true); setUploadResult(null); setMessage(`Analysing ${file.name}…`);
    try {
      const isPcap = file.name.toLowerCase().endsWith(".pcap");
      let payload: { filename: string; content?: string; content_base64?: string };
      if (isPcap) {
        const contentBase64 = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onerror = () => reject(new Error("The PCAP file could not be read."));
          reader.onload = () => {
            const value = String(reader.result ?? "");
            const separator = value.indexOf(",");
            if (separator < 0) reject(new Error("The PCAP file could not be encoded."));
            else resolve(value.slice(separator + 1));
          };
          reader.readAsDataURL(file);
        });
        payload = { filename: file.name, content_base64: contentBase64 };
      } else {
        payload = { filename: file.name, content: await file.text() };
      }
      const result = await api<UploadResult>("/replays/analyse", { method: "POST", body: JSON.stringify(payload) });
      setUploadResult(result);
      setLatestRun(result); setAnalystRunId(result.run_id); setAnalystRun(result); setShowAllQueue(false);
      void loadRunHistory(result);
      const run = { status: "completed", telemetry_status: result.quality.status, elapsed_ms: result.analysis_ms, stages: result.stages };
      setDemoRun(run); await revealStages(result.stages); await refresh(false); setUploadResult(result); setMessage(result.headline);
    } catch (error) { setMessage((error as Error).message); }
    finally { setUploading(false); if (fileInput.current) fileInput.current.value = ""; }
  };
  const setStatus = async (status: string) => {
    if (!selected) return;
    try { await api(`/incidents/${selected.incident_id}/status`, { method: "PATCH", body: JSON.stringify({ status }) }); await openIncident(selected.incident_id); await refresh(false); }
    catch (error) { setMessage((error as Error).message); }
  };
  const submitFeedback = async (disposition: string) => {
    if (!selected) return;
    try {
      await api(`/incidents/${selected.incident_id}/feedback`, { method: "POST", body: JSON.stringify({ disposition, analyst, notes }) });
      setNotes(""); await openIncident(selected.incident_id); await refresh(false); setMessage("Analyst decision saved.");
    } catch (error) { setMessage((error as Error).message); }
  };
  const exportIncident = async () => {
    if (!selected) return;
    const data = await api(`/incidents/${selected.incident_id}/export`);
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `${selected.incident_id}.json`; link.click(); URL.revokeObjectURL(url);
  };
  const stages = demoRun?.stages ?? PIPELINE_TEMPLATE;
  const activeAnalystRun = analystRunId && analystRun?.run_id === analystRunId ? analystRun : null;
  const liveAnalystStream = stream?.status === "running";
  const analystSource = liveAnalystStream ? "Current simulated stream" : activeAnalystRun ? `Saved run · ${activeAnalystRun.filename || "simulated stream"}` : analystRunId ? "Loading saved run" : "All stored incidents";
  const analystScope = liveAnalystStream ? "Provisional findings from the current simulated stream; final evidence is saved on completion." : activeAnalystRun ? `Run ${activeAnalystRun.run_id} only. Capture time and analysis time are shown separately.` : "Stored queue may include incidents from different runs; this is not a single-replay accuracy score.";
  const analystIncidents = liveAnalystStream ? [...new Map((stream?.findings ?? []).map((item) => [item.incident.incident_id, item.incident])).values()] : activeAnalystRun?.incidents ?? (analystRunId ? [] : queueDetails);
  const analystAlerts = liveAnalystStream ? (stream?.findings ?? []).map((item) => item.alert) : activeAnalystRun?.alerts ?? (analystRunId ? [] : queueDetails.flatMap((item) => item.alerts ?? []));
  const reviewAnalystAlert = (alert: Alert) => {
    if (liveAnalystStream) { setMessage("Full incident evidence is available when the stream completes."); return; }
    if (activeAnalystRun) openReplayEvidence(activeAnalystRun, activeAnalystRun.incidents.find((item) => item.alert_ids.includes(alert.alert_id))?.incident_id);
    else { const incident = analystIncidents.find((item) => item.alert_ids.includes(alert.alert_id)); if (incident) void openIncident(incident.incident_id); }
  };
  return <div className="app-shell">
    <header className="topbar">
      <a className="brand" href="/" onClick={(event) => { event.preventDefault(); navigate("workbench"); }}><img className="brand-logo" src="/images/drastha-mark-transparent.png" alt="" width={1536} height={1024} /><span className="brand-wordmark"><b>DRASHTA</b><small>Passive threat review</small></span></a>
      <nav className="workspace-nav" aria-label="Workspace"><span>Workspace</span><a href="/#replay-workbench" aria-current={route === "workbench" ? "page" : undefined} onClick={(event) => { event.preventDefault(); navigate("workbench", "replay-workbench"); }}><Activity size={16} aria-hidden="true" />Replay workbench</a><a href="/analyst" aria-current={route === "analyst" ? "page" : undefined} onClick={(event) => { event.preventDefault(); navigate("analyst"); }}><BarChart3 size={16} aria-hidden="true" />SOC analyst</a><a href="/#investigations" onClick={(event) => { event.preventDefault(); navigate("workbench", "investigations"); }}><Search size={16} aria-hidden="true" />Investigations</a></nav>
      <button className="theme-toggle" type="button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
        {theme === "dark" ? <Sun size={17} aria-hidden="true" /> : <Moon size={17} aria-hidden="true" />}<span>{theme === "dark" ? "Light" : "Dark"}</span>
      </button>
      <div className="system-state"><span><i className={health?.status === "healthy" ? "online" : "offline"} />{health?.status === "healthy" ? "Analysis service ready" : "Checking service"}</span><span>{health?.storage || "local"} storage</span><span>One-way monitoring</span></div>
    </header>

    <main id="top">
      {route === "analyst" ? <AnalystRoute alerts={analystAlerts} incidents={analystIncidents} source={analystSource} scope={analystScope} loading={runHistoryLoading || (analystRunId ? !activeAnalystRun : queueDetailsLoading || loading)} timelineAvailable={Boolean(liveAnalystStream || activeAnalystRun)} history={runHistory} selectedRunId={analystRunId} hasMoreHistory={runHistoryHasMore} selectedRun={activeAnalystRun} onSelectRun={(id) => void selectAnalystRun(id)} onLoadMore={() => void loadOlderRuns()} onReview={reviewAnalystAlert} /> : <>
      <section className="workbench" id="replay-workbench" aria-labelledby="hero-heading">
        <HeroTopology active={running || uploading || stream?.status === "running"} />
        <div className="intro"><p className="eyebrow">Passive near-real-time intelligence</p><h1 id="hero-heading">Watch threats emerge from a one-way IP stream.</h1><p>Drastha passively receives simulated network records, detects and classifies suspicious behaviour, scores the risk and publishes explainable alerts as the stream arrives.</p><div className="intro-actions"><button className="primary" disabled={stream?.status === "running" || running || uploading} onClick={startLiveStream}><Radio size={16} />{stream?.status === "running" ? "Stream running…" : "Start live IP simulation"}<ArrowRight size={17} aria-hidden="true" /></button><button className="text-button" disabled={running || uploading || stream?.status === "running"} onClick={runDemo}><Activity size={14} />Run instant replay</button></div></div>
        <div className="upload-card">
          <div className="upload-title"><FileUp size={19} /><div><b>Analyse your own replay or capture</b><span>Classic PCAP, Zeek metadata, JSONL or JSON · up to 5 MB</span></div></div>
          <button className={`dropzone ${dragging ? "dragging" : ""}`} disabled={uploading || running || stream?.status === "running"} onClick={() => fileInput.current?.click()} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); void analyseFile(event.dataTransfer.files[0]); }}>
            <FileJson size={23} /><b>{uploading ? "Checking the replay…" : "Choose or drop a replay file"}</b><span>The file stays on this computer and is used only for this analysis.</span>
          </button>
          <input ref={fileInput} hidden type="file" accept=".pcap,.jsonl,.ndjson,.json,application/vnd.tcpdump.pcap,application/json" onChange={(event) => void analyseFile(event.target.files?.[0])} />
          <a className="sample-link" href="/api/replays/sample"><Download size={14} />Download a sample attack replay</a>
        </div>
      </section>

      {stream && <section className={`live-panel live-${stream.status}`}>
        <div className="live-head"><div><p className="eyebrow">One-way stream monitor</p><h2>{stream.status === "running" ? "Analysing traffic as it arrives" : stream.status === "complete" ? "Stream analysis complete" : "Stream interrupted"}</h2><p>No packets or commands are sent back to the simulated protected network.</p></div><span className="live-state"><i />{stream.status === "running" ? "Live" : stream.status}</span></div>
        <div className="stream-progress"><div><span>Records analysed</span><b>{stream.processed} / {stream.total || "—"}</b></div><progress value={stream.processed} max={stream.total || 1} /></div>
        <div className="stream-summary">
          <div><span>Labelled alerts</span><b>{stream.findings.length}</b></div>
          <div><span>Current risk</span><b>{stream.riskScore}/100</b></div>
          <div><span>Collection mode</span><b>Passive only</b></div>
          <div><span>Response path</span><b>None</b></div>
        </div>
        {stream.latest && <div className="latest-record"><span>Latest observation</span><b>{stream.latest.src_ip} <ArrowRight size={12} /> {stream.latest.dst_ip}:{stream.latest.dst_port}</b><small>{stream.latest.record_kind === "dns" ? `DNS query · ${stream.latest.query}` : `${stream.latest.protocol.toUpperCase()} · ${stream.latest.outbound_bytes.toLocaleString()} bytes out · flow ${stream.latest.flow_id}`}</small></div>}
        {stream.findings.length > 0 ? <div className="live-findings">{stream.findings.map((item) => <article key={item.alert.alert_id}><div><span className={`severity severity-${item.alert.severity}`}>{item.alert.severity}</span><b>{item.alert.threat_class || label(item.alert.subtype)}</b></div><strong>{Math.round(item.alert.confidence * 100)}% confidence</strong><p>{item.detection_method}</p><small>{item.alert.evidence[0]?.explanation}</small></article>)}</div> : <div className="listening"><Radio size={15} /><span>{stream.status === "running" ? "Listening for behaviour that crosses a detection threshold…" : "No configured threat behaviour was found."}</span></div>}
        {stream.status === "complete" && stream.topIncidentId && <button className="secondary live-review" onClick={() => void openIncident(stream.topIncidentId!)}><Eye size={15} />Open scored intelligence</button>}
        {stream.findings.length > 0 && <button className="secondary live-review" onClick={() => navigate("analyst")}><BarChart3 size={15} />Visualise attack patterns</button>}
        <FeatureCoverageNote value={stream.featureCoverage} />
      </section>}

      {uploadResult && <section className={`result-panel ${uploadResult.verdict === "threat_detected" ? "result-danger" : "result-clear"}`}>
        <div className="result-heading"><div className="verdict-icon">{uploadResult.verdict === "threat_detected" ? <CircleAlert size={22} /> : <Check size={22} />}</div><div><p className="eyebrow">Uploaded replay result · {uploadResult.filename}</p><h2>{uploadResult.headline}</h2><p>{uploadResult.summary}</p></div><button className="secondary" onClick={() => openReplayEvidence(uploadResult)}><Eye size={15} />Review full evidence</button></div>
        {uploadResult.overall_risk && <OverallRisk value={uploadResult.overall_risk} label={label} />}
        <ReplayOutcomeStatus result={uploadResult} />
        <button className="secondary visualise-replay" onClick={() => navigate("analyst")}><BarChart3 size={15} />Visualise attack patterns</button>
        <div className="result-facts"><span><b>{uploadResult.quality.records_accepted}/{uploadResult.quality.records_received}</b> accepted records</span><span><b>{uploadResult.quality.records_rejected}</b> rejected</span><span><b>{uploadResult.quality.out_of_order_records}</b> out of order</span><span><b>{uploadResult.quality.duplicate_uid_count}</b> duplicate UIDs</span><span><b>{uploadResult.alerts.length}</b> findings</span><span><b>{uploadResult.incidents.length}</b> incidents</span><span><b>{uploadResult.analysis_ms} ms</b> analysis time</span><span><b>{uploadResult.quality.status}</b> data quality</span>{uploadResult.telemetry && <><span><b>{uploadResult.telemetry.dns_records}</b> DNS records</span><span><b>{uploadResult.telemetry.encrypted_session_records}</b> TLS records</span></>}{uploadResult.context_policy && <span><b>{uploadResult.context_policy.suppressed_connection_evaluations}</b> policy-approved records</span>}</div>
        {uploadResult.quality.degraded_reasons.length > 0 && <p className="scope-note"><b>Data-quality reason:</b> {uploadResult.quality.degraded_reasons.join("; ")}</p>}
        <FeatureCoverageNote value={uploadResult.feature_coverage} />
        {uploadResult.quality.errors.length > 0 && <p className="scope-note"><b>Quarantine sample:</b> {uploadResult.quality.errors.join(" · ")}</p>}
        {uploadResult.evaluation && <div className="result-facts"><span><b>{uploadResult.evaluation.true_positive}</b> TP</span><span><b>{uploadResult.evaluation.false_positive}</b> FP</span><span><b>{uploadResult.evaluation.false_negative}</b> FN</span><span><b>{uploadResult.evaluation.true_negative}</b> TN</span><span><b>{Math.round(uploadResult.evaluation.precision * 100)}%</b> precision</span><span><b>{Math.round(uploadResult.evaluation.recall * 100)}%</b> recall</span><span><b>{Math.round(uploadResult.evaluation.f1_score * 100)}%</b> F1</span><span><b>{Math.round(uploadResult.evaluation.false_positive_rate * 100)}%</b> FPR</span></div>}
        {uploadResult.evaluation && <p className="scope-note">These are behaviour-level scores against labels in this replay, not independent production accuracy. Separately pinned datasets are evaluated with the offline corpus workflow; unknown/background traffic is not assumed benign.</p>}
        {uploadResult.alerts.length > 0 && <div className="finding-list">{uploadResult.alerts.map((alert) => <article className="finding" key={alert.alert_id}><div className="finding-top"><div><span className={`severity severity-${alert.severity}`}>{alert.severity}</span><h3>{alert.threat_class || label(alert.subtype)}</h3></div><b>{Math.round(alert.confidence * 100)}% confidence</b></div><p className="route">{alert.src_ip} <ArrowRight size={13} /> {alert.dst_ip || "multiple destinations"}</p><p className="finding-meaning">{label(alert.subtype)}</p><div className="evidence-list">{alert.evidence.slice(0, 4).map((item) => <div key={item.name}><span>{label(item.name)}</span><b>{item.observed}</b><small>{item.explanation}</small></div>)}</div><p className="caveat"><b>Keep in mind:</b> {alert.limitations[0]}</p><button className="secondary" onClick={() => openReplayEvidence(uploadResult, uploadResult.incidents.find((item) => item.alert_ids.includes(alert.alert_id))?.incident_id)}><Eye size={14} />Review this incident</button></article>)}</div>}
        <p className="scope-note">{uploadResult.scope_note}</p>
      </section>}

      <section className="pipeline-section"><div className="section-head"><div><p className="eyebrow">How the result was produced</p><h2>Replay to insight</h2></div><span>{demoRun ? `${demoRun.telemetry_status} data · ${demoRun.elapsed_ms ?? "—"} ms` : "Ready"}</span></div><ol className="pipeline">{stages.map((stage, index) => { const visible = !running && !uploading || index < visibleStages; const count = stage.alerts !== undefined ? `${stage.alerts} findings` : stage.incidents !== undefined ? `${stage.incidents} incidents` : stage.records !== undefined ? `${stage.records} records` : ""; return <li className={visible ? `step step-${stage.status}` : "step pending"} key={`${stage.name}-${index}`}><span>{visible ? <Check size={13} /> : index + 1}</span><div><b>{stage.name}</b><p>{stage.detail}</p><small>{visible ? count : "Waiting"}{visible && stage.duration_ms !== undefined ? ` · ${stage.duration_ms} ms` : ""}</small></div></li>; })}</ol></section>

      <section className="overview" id="investigations"><div className="section-head"><div><p className="eyebrow">What needs attention</p><h2>Investigation queue</h2></div><div className="investigation-actions"><div className="plain-metrics"><span><b>{latestRun && !showAllQueue ? latestRun.incidents.filter((item) => item.status === "open" || item.status === "investigating").length : metrics?.active_incidents ?? "—"}</b> active</span><span><b>{latestRun && !showAllQueue ? latestRun.incidents.filter((item) => item.severity === "critical").length : metrics?.critical_incidents ?? "—"}</b> critical</span><span><b>{metrics?.feedback_records ?? "—"}</b> all-time reviews</span></div><button className="secondary" onClick={() => { void refresh(false); void loadRunHistory(); }} disabled={loading}><RefreshCw size={15} className={loading ? "spin" : ""} />Refresh queue</button></div></div>
        <div className="queue-scope"><span>{latestRun && !showAllQueue ? <>Latest analysis: <b>{latestRun.analysed_at ? timeLabel(latestRun.analysed_at) : "time unavailable"}</b> · {latestRun.filename || "simulated stream"}. Dates below are <b>capture times</b> from the input, not today's analysis time.</> : "All saved incidents · historical capture times; entries may span separate replays."}</span>{latestRun && <div><button type="button" aria-pressed={!showAllQueue} onClick={() => setShowAllQueue(false)}>Latest run</button><button type="button" aria-pressed={showAllQueue} onClick={() => setShowAllQueue(true)}>All history</button></div>}</div>
        <div className="queue-tools"><label><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search device, incident or behaviour" /></label><label><Filter size={14} /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All priorities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></div>
        {loading || runHistoryLoading ? <div className="empty"><RefreshCw className="spin" />Loading incidents…</div> : filtered.length === 0 ? <div className="empty"><Network size={22} /><b>No matching incidents in this view</b><span>{latestRun && !showAllQueue ? "The latest run raised no incident here. Switch to All history to review older incidents." : "Run or upload a replay to analyse network behaviour."}</span></div> : <div className="incident-list">{filtered.map((item) => <button key={item.incident_id} onClick={() => void openIncident(item.incident_id, latestRun && !showAllQueue ? item.alert_ids : undefined, latestRun && !showAllQueue ? latestRun : undefined)}><div className={`risk risk-${item.severity}`}><b>{item.risk_score}</b><span>risk</span></div><div className="incident-main"><b>{item.threat_types.map(label).join(" + ")}</b><span>{item.src_ip} · {item.detector_ids.length} independent checks</span></div><span className={`severity severity-${item.severity}`}>{item.severity}</span><span className="incident-status">{label(item.status)}</span><time>{latestRun && !showAllQueue && latestRun.analysed_at ? <><b title="When Drastha analysed the replay">Analysed {timeLabel(latestRun.analysed_at)}</b><small title="Timestamp preserved from source traffic">Captured {timeLabel(item.last_seen)}</small></> : <>Captured {timeLabel(item.last_seen)}</>}</time><ChevronRight size={17} /></button>)}</div>}
      </section>
      </>}
    </main>

    {evidenceRun && <ReplayEvidence key={`${evidenceRun.run.run_id}:${evidenceRun.incidentId ?? "all"}`} run={evidenceRun.run} initialIncidentId={evidenceRun.incidentId} label={label} onClose={closeEvidence} />}
    {selected && <div className="drawer-backdrop" onMouseDown={(event) => { if (event.currentTarget === event.target) closeEvidence(); }}><aside className="drawer" aria-label="Incident details"><div className="drawer-head"><div><p className="eyebrow">Incident review · latest saved state</p><h2>{selected.threat_types.map(label).join(" + ")}</h2><span>{selected.src_ip} · #{selected.incident_id}</span></div><button aria-label="Close" onClick={closeEvidence}><X size={19} /></button></div><div className="incident-verdict"><div className={`risk risk-${selected.severity}`}><b>{selected.risk_score}</b><span>risk</span></div><div><b>{selected.severity} priority</b><span>{Math.round(selected.confidence * 100)}% detector confidence</span><small>Risk is investigation priority, not certainty.</small></div></div><div className="drawer-actions"><label><span>Status</span><select value={selected.status} onChange={(event) => void setStatus(event.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></label><button onClick={() => void exportIncident()}><Download size={14} />Export evidence</button></div>
        <IncidentConclusion value={selected.conclusion} />
        <section className="detail-section"><h3>Detection timeline</h3><div className="timeline">{selected.alerts?.map((alert, index) => <article key={alert.alert_id}><span>{index + 1}</span><div><time>{timeLabel(alert.window_start, selected.first_seen)}</time><b>{label(alert.subtype)}</b><p>{alert.src_ip} → {alert.dst_ip || "multiple destinations"}</p></div></article>)}</div></section>
        <section className="detail-section"><h3>Supporting measurements</h3>{selected.alerts?.map((alert) => <div className="detail-finding" key={alert.alert_id}><div><b>{label(alert.subtype)}</b><span>{Math.round(alert.confidence * 100)}% confidence</span></div><div className="evidence-list">{alert.evidence.map((item) => <div key={item.name}><span>{label(item.name)}</span><b>{item.observed}</b><small>{item.explanation}</small><em>{item.comparison}</em></div>)}</div><p className="caveat"><b>Possible alternative:</b> {alert.limitations[0]}</p></div>)}</section>
        <section className="detail-section"><h3>Priority score</h3><div className="score-list">{selected.scoring_factors.map((item) => <div key={item.name}><span>{label(item.name)}</span><b>+{item.observed}</b><small>{item.explanation}</small></div>)}</div></section>
        <section className="detail-section"><h3>Record the decision</h3><div className="review-form"><input value={analyst} onChange={(event) => setAnalyst(event.target.value)} placeholder="Analyst name" /><textarea value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="What did you verify?" rows={3} /><div><button className="danger" onClick={() => void submitFeedback("confirmed_malicious")}>Malicious</button><button onClick={() => void submitFeedback("needs_review")}>Needs review</button><button onClick={() => void submitFeedback("benign")}>Benign</button></div></div>{!!selected.feedback?.length && <div className="feedback-list">{selected.feedback.map((item) => <article key={item.feedback_id}><b>{label(item.disposition)}</b><span>{item.analyst}</span><p>{item.notes || "No notes added."}</p></article>)}</div>}</section>
      </aside></div>}
    {message && <button className="toast" onClick={() => setMessage("")}>{message}<X size={14} /></button>}
  </div>;
}

export default App;
