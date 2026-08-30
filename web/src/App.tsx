import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, ArrowRight, Check, ChevronRight, CircleAlert, Download, Eye,
  FileJson, FileUp, Filter, Network, RefreshCw, Search, Shield, X,
} from "lucide-react";

type Evidence = { name: string; observed: number | string; comparison: string; explanation: string };
type Alert = {
  alert_id: string; detector_id: string; threat_type: string; subtype: string;
  severity: string; confidence: number; window_start: number; window_end: number;
  src_ip: string; dst_ip?: string; evidence: Evidence[]; limitations: string[];
};
type Feedback = { feedback_id: string; disposition: string; analyst: string; timestamp: number; notes: string };
type Incident = {
  incident_id: string; src_ip: string; first_seen: number; last_seen: number;
  alert_ids: string[]; detector_ids: string[]; threat_types: string[];
  confidence: number; risk_score: number; severity: string; status: string;
  scoring_factors: Evidence[]; alerts?: Alert[]; feedback?: Feedback[];
};
type Metrics = { total_incidents: number; active_incidents: number; critical_incidents: number; feedback_records: number; average_risk_score: number };
type DemoStage = { name: string; status: string; detail: string; duration_ms?: number; records?: number; rejected?: number; alerts?: number; incidents?: number };
type DemoRun = { status: string; telemetry_status: string; elapsed_ms?: number; stages: DemoStage[] };
type Health = { status: string; mode: string; storage: string; return_path_required: boolean; demo_run?: DemoRun | null };
type UploadResult = {
  verdict: string; headline: string; summary: string; filename: string; file_size_bytes: number;
  analysis_ms: number; quality: { status: string; records_accepted: number; records_rejected: number; errors: string[] };
  alerts: Alert[]; incidents: Incident[]; top_incident_id?: string; stages: DemoStage[]; scope_note: string;
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
  reconnaissance: "Network reconnaissance", denial_of_service: "Traffic flooding",
  periodic_beacon: "Repeated callback pattern", outbound_volume_anomaly: "Unusual outbound data transfer",
  vertical_port_scan: "Many ports checked on one device", horizontal_host_scan: "One service checked across many devices",
  syn_flood: "Many incomplete connection attempts", udp_flood: "Unusually high UDP traffic",
};
const label = (value: string) => LABELS[value] || value.replaceAll("_", " ");
const timeLabel = (value: number, origin?: number) => value < 946684800
  ? origin === undefined ? `Capture +${Math.round(value)}s` : `+${Math.max(0, Math.round(value - origin))}s`
  : new Date(value * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, { headers: { "Content-Type": "application/json", ...options?.headers }, ...options });
  if (!response.ok) throw new Error((await response.json()).detail || "Request failed");
  return response.json();
}

function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [selected, setSelected] = useState<Incident | null>(null);
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
  const fileInput = useRef<HTMLInputElement>(null);

  const refresh = async (keepSelection = true) => {
    setLoading(true);
    try {
      const [queue, summary, service] = await Promise.all([api<Incident[]>("/incidents"), api<Metrics>("/metrics"), api<Health>("/health")]);
      setIncidents(queue); setMetrics(summary); setHealth(service);
      if (service.demo_run) { setDemoRun(service.demo_run); setVisibleStages(service.demo_run.stages.length); }
      if (keepSelection && selected) setSelected(await api<Incident>(`/incidents/${selected.incident_id}`));
    } catch (error) { setMessage((error as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { void refresh(false); }, []);

  const filtered = useMemo(() => incidents.filter((item) => {
    const text = `${item.src_ip} ${item.incident_id} ${item.threat_types.join(" ")}`.toLowerCase();
    return text.includes(query.toLowerCase()) && (severity === "all" || item.severity === severity);
  }), [incidents, query, severity]);
  const openIncident = async (id: string) => {
    try { setSelected(await api<Incident>(`/incidents/${id}`)); }
    catch (error) { setMessage((error as Error).message); }
  };
  const revealStages = async (stages: DemoStage[]) => {
    setVisibleStages(0);
    for (let index = 1; index <= stages.length; index += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 180)); setVisibleStages(index);
    }
  };
  const runDemo = async () => {
    setRunning(true); setUploadResult(null); setMessage("Running the known attack replay…");
    try {
      const result = await api<DemoRun>("/demo/run", { method: "POST" });
      setDemoRun(result); await revealStages(result.stages); await refresh(false);
      setMessage(`Replay complete. A critical incident was created in ${result.elapsed_ms ?? "—"} ms.`);
    } catch (error) { setMessage((error as Error).message); }
    finally { setRunning(false); }
  };
  const analyseFile = async (file?: File) => {
    if (!file) return;
    if (file.size > 5_000_000) { setMessage("Choose a replay smaller than 5 MB."); return; }
    setUploading(true); setUploadResult(null); setMessage(`Analysing ${file.name}…`);
    try {
      const content = await file.text();
      const result = await api<UploadResult>("/replays/analyse", { method: "POST", body: JSON.stringify({ filename: file.name, content }) });
      setUploadResult(result);
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

  return <div className="app-shell">
    <header className="topbar">
      <a className="brand" href="#top"><span><Shield size={18} /></span><div><b>Drastha</b><small>Passive threat review</small></div></a>
      <div className="system-state"><span><i className={health?.status === "healthy" ? "online" : "offline"} />{health?.status === "healthy" ? "Sensor online" : "Checking sensor"}</span><span>{health?.storage || "local"} storage</span><span>One-way monitoring</span></div>
    </header>

    <main id="top">
      <section className="workbench">
        <div className="intro"><p className="eyebrow">Threat investigation</p><h1>Understand what happened on the network.</h1><p>Run our known scenario or upload a safe network replay. Drastha explains the behaviour it found and the evidence behind it.</p><button className="primary" disabled={running || uploading} onClick={runDemo}><Activity size={16} />{running ? "Analysing replay…" : "Run known attack replay"}</button></div>
        <div className="upload-card">
          <div className="upload-title"><FileUp size={19} /><div><b>Analyse your own replay</b><span>Zeek connection records · JSONL or JSON · up to 5 MB</span></div></div>
          <button className={`dropzone ${dragging ? "dragging" : ""}`} disabled={uploading || running} onClick={() => fileInput.current?.click()} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); void analyseFile(event.dataTransfer.files[0]); }}>
            <FileJson size={23} /><b>{uploading ? "Checking the replay…" : "Choose or drop a replay file"}</b><span>The file stays on this computer and is used only for this analysis.</span>
          </button>
          <input ref={fileInput} hidden type="file" accept=".jsonl,.ndjson,.json,application/json" onChange={(event) => void analyseFile(event.target.files?.[0])} />
          <a className="sample-link" href="/api/replays/sample"><Download size={14} />Download a sample attack replay</a>
        </div>
      </section>

      {uploadResult && <section className={`result-panel ${uploadResult.verdict === "threat_detected" ? "result-danger" : "result-clear"}`}>
        <div className="result-heading"><div className="verdict-icon">{uploadResult.verdict === "threat_detected" ? <CircleAlert size={22} /> : <Check size={22} />}</div><div><p className="eyebrow">Uploaded replay result</p><h2>{uploadResult.headline}</h2><p>{uploadResult.summary}</p></div>{uploadResult.top_incident_id && <button className="secondary" onClick={() => void openIncident(uploadResult.top_incident_id!)}><Eye size={15} />Review full evidence</button>}</div>
        <div className="result-facts"><span><b>{uploadResult.quality.records_accepted}</b> valid records</span><span><b>{uploadResult.alerts.length}</b> findings</span><span><b>{uploadResult.incidents.length}</b> incidents</span><span><b>{uploadResult.analysis_ms} ms</b> analysis time</span><span><b>{uploadResult.quality.status}</b> data quality</span></div>
        {uploadResult.alerts.length > 0 && <div className="finding-list">{uploadResult.alerts.map((alert) => <article className="finding" key={alert.alert_id}><div className="finding-top"><div><span className={`severity severity-${alert.severity}`}>{alert.severity}</span><h3>{label(alert.subtype)}</h3></div><b>{Math.round(alert.confidence * 100)}% confidence</b></div><p className="route">{alert.src_ip} <ArrowRight size={13} /> {alert.dst_ip || "multiple destinations"}</p><p className="finding-meaning">{label(alert.threat_type)}</p><div className="evidence-list">{alert.evidence.slice(0, 4).map((item) => <div key={item.name}><span>{label(item.name)}</span><b>{item.observed}</b><small>{item.explanation}</small></div>)}</div><p className="caveat"><b>Keep in mind:</b> {alert.limitations[0]}</p></article>)}</div>}
        <p className="scope-note">{uploadResult.scope_note}</p>
      </section>}

      <section className="pipeline-section"><div className="section-head"><div><p className="eyebrow">How the result was produced</p><h2>Replay to insight</h2></div><span>{demoRun ? `${demoRun.telemetry_status} data · ${demoRun.elapsed_ms ?? "—"} ms` : "Ready"}</span></div><ol className="pipeline">{stages.map((stage, index) => { const visible = !running && !uploading || index < visibleStages; const count = stage.alerts !== undefined ? `${stage.alerts} findings` : stage.incidents !== undefined ? `${stage.incidents} incidents` : stage.records !== undefined ? `${stage.records} records` : ""; return <li className={visible ? `step step-${stage.status}` : "step pending"} key={`${stage.name}-${index}`}><span>{visible ? <Check size={13} /> : index + 1}</span><div><b>{stage.name}</b><p>{stage.detail}</p><small>{visible ? count : "Waiting"}{visible && stage.duration_ms !== undefined ? ` · ${stage.duration_ms} ms` : ""}</small></div></li>; })}</ol></section>

      <section className="overview"><div className="section-head"><div><p className="eyebrow">What needs attention</p><h2>Investigation queue</h2></div><div className="plain-metrics"><span><b>{metrics?.active_incidents ?? "—"}</b> active</span><span><b>{metrics?.critical_incidents ?? "—"}</b> critical</span><span><b>{metrics?.feedback_records ?? "—"}</b> reviewed</span></div></div><div className="queue-tools"><label><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search device, incident or behaviour" /></label><label><Filter size={14} /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All priorities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></div>
        {loading ? <div className="empty"><RefreshCw className="spin" />Loading incidents…</div> : filtered.length === 0 ? <div className="empty"><Network size={22} /><b>No matching incidents</b><span>Run or upload a replay to analyse network behaviour.</span></div> : <div className="incident-list">{filtered.map((item) => <button key={item.incident_id} onClick={() => void openIncident(item.incident_id)}><div className={`risk risk-${item.severity}`}><b>{item.risk_score}</b><span>risk</span></div><div className="incident-main"><b>{item.threat_types.map(label).join(" + ")}</b><span>{item.src_ip} · {item.detector_ids.length} independent checks</span></div><span className={`severity severity-${item.severity}`}>{item.severity}</span><span className="incident-status">{label(item.status)}</span><time>{timeLabel(item.last_seen)}</time><ChevronRight size={17} /></button>)}</div>}
      </section>
    </main>

    {selected && <div className="drawer-backdrop" onMouseDown={(event) => { if (event.currentTarget === event.target) setSelected(null); }}><aside className="drawer" aria-label="Incident details"><div className="drawer-head"><div><p className="eyebrow">Incident review</p><h2>{selected.threat_types.map(label).join(" + ")}</h2><span>{selected.src_ip} · #{selected.incident_id}</span></div><button aria-label="Close" onClick={() => setSelected(null)}><X size={19} /></button></div><div className="incident-verdict"><div className={`risk risk-${selected.severity}`}><b>{selected.risk_score}</b><span>risk</span></div><div><b>{selected.severity} priority</b><span>{Math.round(selected.confidence * 100)}% detector confidence</span><small>Risk is investigation priority, not certainty.</small></div></div><div className="drawer-actions"><label><span>Status</span><select value={selected.status} onChange={(event) => void setStatus(event.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></label><button onClick={() => void exportIncident()}><Download size={14} />Export evidence</button></div>
        <section className="detail-section"><h3>What happened</h3><div className="timeline">{selected.alerts?.map((alert, index) => <article key={alert.alert_id}><span>{index + 1}</span><div><time>{timeLabel(alert.window_start, selected.first_seen)}</time><b>{label(alert.subtype)}</b><p>{alert.src_ip} → {alert.dst_ip || "multiple destinations"}</p></div></article>)}</div></section>
        <section className="detail-section"><h3>Why Drastha flagged it</h3>{selected.alerts?.map((alert) => <div className="detail-finding" key={alert.alert_id}><div><b>{label(alert.subtype)}</b><span>{Math.round(alert.confidence * 100)}% confidence</span></div><div className="evidence-list">{alert.evidence.map((item) => <div key={item.name}><span>{label(item.name)}</span><b>{item.observed}</b><small>{item.explanation}</small><em>{item.comparison}</em></div>)}</div><p className="caveat"><b>Possible alternative:</b> {alert.limitations[0]}</p></div>)}</section>
        <section className="detail-section"><h3>Why it is prioritized</h3><div className="score-list">{selected.scoring_factors.map((item) => <div key={item.name}><span>{label(item.name)}</span><b>+{item.observed}</b><small>{item.explanation}</small></div>)}</div></section>
        <section className="detail-section"><h3>Record the decision</h3><div className="review-form"><input value={analyst} onChange={(event) => setAnalyst(event.target.value)} placeholder="Analyst name" /><textarea value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="What did you verify?" rows={3} /><div><button className="danger" onClick={() => void submitFeedback("confirmed_malicious")}>Malicious</button><button onClick={() => void submitFeedback("needs_review")}>Needs review</button><button onClick={() => void submitFeedback("benign")}>Benign</button></div></div>{!!selected.feedback?.length && <div className="feedback-list">{selected.feedback.map((item) => <article key={item.feedback_id}><b>{label(item.disposition)}</b><span>{item.analyst}</span><p>{item.notes || "No notes added."}</p></article>)}</div>}</section>
      </aside></div>}
    {message && <button className="toast" onClick={() => setMessage("")}>{message}<X size={14} /></button>}
  </div>;
}

export default App;
