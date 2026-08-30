import { useEffect, useMemo, useState } from "react";
import {
  Activity, CheckCircle2, ChevronRight, CircleDot, Clock3, Database, Eye,
  FileDown, Filter, Fingerprint, Gauge, LockKeyhole, Network, Radar,
  RefreshCw, Search, Server, ShieldAlert, ShieldCheck, Signal, Sparkles,
  TriangleAlert, UserRoundCheck, Workflow, X,
} from "lucide-react";

type Evidence = { name: string; observed: number | string; comparison: string; explanation: string };
type Alert = {
  alert_id: string; detector_id: string; threat_type: string; subtype: string;
  severity: string; confidence: number; window_start: number; window_end: number;
  dst_ip?: string; evidence: Evidence[]; limitations: string[];
};
type Feedback = {
  feedback_id: string; disposition: string; analyst: string; timestamp: number; notes: string;
};
type Incident = {
  incident_id: string; src_ip: string; first_seen: number; last_seen: number;
  alert_ids: string[]; detector_ids: string[]; threat_types: string[];
  confidence: number; risk_score: number; severity: string; status: string;
  scoring_factors: Evidence[]; alerts?: Alert[]; feedback?: Feedback[];
};
type Metrics = {
  total_incidents: number; active_incidents: number; critical_incidents: number;
  feedback_records: number; average_risk_score: number;
};
type Health = {
  status: string; mode: string; storage: string; return_path_required: boolean;
};

const API = "/api";
const pretty = (value: string) => value.replaceAll("_", " ");
const durationLabel = (seconds: number) => {
  const safe = Math.max(0, Math.round(seconds));
  const minutes = Math.floor(safe / 60);
  const remainder = safe % 60;
  return minutes ? `${minutes}m ${remainder.toString().padStart(2, "0")}s` : `${remainder}s`;
};
const timeLabel = (value: number, origin?: number) => {
  if (value < 946684800) {
    return origin === undefined
      ? `Capture T+${durationLabel(value)}`
      : `+${durationLabel(value - origin)}`;
  }
  return new Date(value * 1000).toLocaleString([], {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
};

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers }, ...options,
  });
  if (!response.ok) throw new Error((await response.json()).detail || "Request failed");
  return response.json();
}

function MetricCard({ label, value, note, icon: Icon, tone = "mint" }: {
  label: string; value: string | number; note: string; icon: typeof Activity; tone?: string;
}) {
  return <article className={`metric ${tone}`}>
    <div className="metric-top"><span>{label}</span><Icon size={18} /></div>
    <strong>{value}</strong><small>{note}</small><div className="metric-line" />
  </article>;
}

function SeverityPill({ value }: { value: string }) {
  return <span className={`pill severity-${value}`}>{value}<CircleDot size={11} /></span>;
}

function EmptyState({ onLoad }: { onLoad: () => void }) {
  return <div className="empty-state">
    <div className="empty-icon"><Radar size={32} /></div>
    <p className="eyebrow">Demo workspace ready</p>
    <h2>Run the multi-stage threat scenario</h2>
    <p>Load a safe offline fixture to demonstrate detection, correlation and analyst review.</p>
    <button className="primary" onClick={onLoad}><Sparkles size={16} /> Run demo scenario</button>
  </div>;
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

  const refresh = async (keepSelection = true) => {
    setLoading(true);
    try {
      const [queue, summary, service] = await Promise.all([
        api<Incident[]>("/incidents"), api<Metrics>("/metrics"), api<Health>("/health"),
      ]);
      setIncidents(queue); setMetrics(summary); setHealth(service);
      if (keepSelection && selected) {
        setSelected(await api<Incident>(`/incidents/${selected.incident_id}`));
      }
    } catch (error) { setMessage((error as Error).message); }
    finally { setLoading(false); }
  };

  useEffect(() => { void refresh(false); }, []);
  const filtered = useMemo(() => incidents.filter((item) => {
    const matchesText = `${item.src_ip} ${item.incident_id} ${item.threat_types.join(" ")}`
      .toLowerCase().includes(query.toLowerCase());
    return matchesText && (severity === "all" || item.severity === severity);
  }), [incidents, query, severity]);
  const highestPriority = incidents[0];

  const openIncident = async (id: string) => {
    try { setSelected(await api<Incident>(`/incidents/${id}`)); }
    catch (error) { setMessage((error as Error).message); }
  };
  const loadDemo = async () => {
    setMessage("Preparing the offline threat scenario…");
    try {
      await api("/demo/load", { method: "POST" });
      setMessage("Demo scenario ready — open the critical incident.");
      await refresh(false);
    } catch (error) { setMessage((error as Error).message); }
  };
  const setStatus = async (status: string) => {
    if (!selected) return;
    try {
      await api(`/incidents/${selected.incident_id}/status`, {
        method: "PATCH", body: JSON.stringify({ status }),
      });
      setMessage(`Incident marked ${pretty(status)}.`); await refresh();
    } catch (error) { setMessage((error as Error).message); }
  };
  const submitFeedback = async (disposition: string) => {
    if (!selected) return;
    try {
      await api(`/incidents/${selected.incident_id}/feedback`, {
        method: "POST", body: JSON.stringify({ disposition, analyst, notes }),
      });
      setNotes(""); setMessage("Analyst decision recorded."); await refresh();
    } catch (error) { setMessage((error as Error).message); }
  };
  const exportIncident = async () => {
    if (!selected) return;
    const data = await api(`/incidents/${selected.incident_id}/export`);
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `${selected.incident_id}.json`; link.click();
    URL.revokeObjectURL(url); setMessage("Incident export downloaded.");
  };

  return <div className="shell">
    <header className="topbar">
      <div className="brand"><div className="brandmark"><ShieldCheck size={22} /></div>
        <div><b>Drastha</b><span>Passive Threat Intelligence</span></div></div>
      <div className="header-status">
        <span><Signal size={13} /> Sensor <b>{health?.status === "healthy" ? "ONLINE" : "CHECKING"}</b></span>
        <span><Database size={13} /> {health?.storage ?? "storage"}</span>
        <span><LockKeyhole size={13} /> No return path</span>
      </div>
      <button className="icon-button" onClick={() => void refresh()} aria-label="Refresh queue"><RefreshCw size={17} /></button>
    </header>

    <main>
      <section className="hero">
        <div className="hero-copy">
          <div className="hero-kicker"><span>SIH Demo Console</span><span className="live-dot">Passive monitoring</span></div>
          <h1>See the attack story.<br /><em>Not just another alert.</em></h1>
          <p>Drastha converts one-way network telemetry into explainable, correlated incidents without decrypting payloads or contacting the protected network.</p>
          <div className="hero-actions">
            {highestPriority
              ? <button className="primary" onClick={() => void openIncident(highestPriority.incident_id)}><Eye size={16} /> Investigate top incident</button>
              : <button className="primary" onClick={loadDemo}><Sparkles size={16} /> Run demo scenario</button>}
            <span><Server size={14} /> Offline-ready deployment</span>
          </div>
        </div>
        <div className="story-card">
          <div className="story-head"><span>DEMO ATTACK CHAIN</span><Workflow size={17} /></div>
          <div className="story-step"><b>01</b><div><strong>Periodic callback</strong><span>C2-like beacon behaviour</span></div><Activity size={17} /></div>
          <div className="story-connector" />
          <div className="story-step"><b>02</b><div><strong>Outbound anomaly</strong><span>Unusual data transfer volume</span></div><Network size={17} /></div>
          <div className="story-connector" />
          <div className="story-step critical-step"><b>03</b><div><strong>Critical incident</strong><span>Cross-detector correlation</span></div><ShieldAlert size={17} /></div>
        </div>
      </section>

      <section className="trust-strip">
        <span><Fingerprint size={15} /><b>Evidence first</b> every alert explains why</span>
        <span><LockKeyhole size={15} /><b>One-way safe</b> zero response traffic</span>
        <span><Gauge size={15} /><b>Transparent score</b> confidence stays separate</span>
      </section>

      <section className="section-heading">
        <div><p className="eyebrow">Live operational snapshot</p><h2>Threat operations overview</h2></div>
        <div className="freshness"><Clock3 size={15} /><span>Updated</span><b>just now</b></div>
      </section>

      <section className="metrics-grid">
        <MetricCard label="Active incidents" value={metrics?.active_incidents ?? "—"} note="Requires analyst attention" icon={ShieldAlert} tone="coral" />
        <MetricCard label="Critical" value={metrics?.critical_incidents ?? "—"} note="Highest-priority cases" icon={Activity} tone="amber" />
        <MetricCard label="Average risk" value={metrics ? `${metrics.average_risk_score}/100` : "—"} note="Policy score, not confidence" icon={Radar} />
        <MetricCard label="Reviewed" value={metrics?.feedback_records ?? "—"} note="Analyst decisions retained" icon={UserRoundCheck} tone="blue" />
      </section>

      <section className="workspace">
        <div className="queue-panel">
          <div className="panel-head"><div><p className="eyebrow">Prioritized investigation queue</p><h2>Incidents</h2><span>{filtered.length} result{filtered.length === 1 ? "" : "s"} ordered by risk</span></div>
            <div className="filters"><label className="search"><Search size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search IP, ID or threat" /></label>
              <label className="select"><Filter size={14} /><select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="all">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></div></div>

          {loading ? <div className="loading"><RefreshCw className="spin" /> Synchronizing incident queue…</div> :
            incidents.length === 0 ? <EmptyState onLoad={loadDemo} /> : filtered.length === 0 ?
              <div className="no-results"><Search size={24} /><b>No matching incidents</b><span>Change the search text or severity filter.</span></div> :
            <div className="table-wrap"><table><thead><tr><th>Risk</th><th>Source</th><th>Threat story</th><th>Severity</th><th>Status</th><th>Last seen</th><th></th></tr></thead>
              <tbody>{filtered.map((item) => <tr key={item.incident_id} tabIndex={0} onClick={() => void openIncident(item.incident_id)} onKeyDown={(event) => { if (event.key === "Enter") void openIncident(item.incident_id); }}>
                <td><div className={`risk risk-${item.severity}`}>{item.risk_score}</div></td>
                <td><b className="mono">{item.src_ip}</b><small className="mono">#{item.incident_id.slice(0, 8)}</small></td>
                <td><div className="threat-list">{item.threat_types.map((threat) => <span key={threat}>{pretty(threat)}</span>)}</div><small>{item.detector_ids.length} contributing detector{item.detector_ids.length === 1 ? "" : "s"}</small></td>
                <td><SeverityPill value={item.severity} /></td><td><span className={`status status-${item.status}`}>{pretty(item.status)}</span></td>
                <td className="time">{timeLabel(item.last_seen)}</td><td><ChevronRight size={17} /></td>
              </tr>)}</tbody></table></div>}
        </div>
      </section>
    </main>

    {selected && <div className="drawer-backdrop" onMouseDown={(event) => { if (event.currentTarget === event.target) setSelected(null); }}>
      <aside className="drawer" aria-label="Incident evidence drawer">
        <div className="drawer-head"><div><p className="eyebrow">Incident investigation</p><h2>{selected.src_ip}</h2><span className="mono">#{selected.incident_id}</span></div><button className="icon-button" aria-label="Close incident" onClick={() => setSelected(null)}><X size={19} /></button></div>

        <div className="story-verdict"><TriangleAlert size={19} /><div><b>Multi-stage suspicious behaviour detected</b><span>{selected.detector_ids.length} independent detectors contributed to this incident.</span></div></div>
        <div className="incident-summary"><div className={`score score-${selected.severity}`}><strong>{selected.risk_score}</strong><span>risk score</span></div>
          <div className="summary-copy"><SeverityPill value={selected.severity} /><p><b>{Math.round(selected.confidence * 100)}%</b> detector confidence</p><small>Risk is a transparent policy priority. Confidence represents detector certainty.</small></div></div>
        <div className="action-row"><label><span>Workflow status</span><select aria-label="Workflow status" value={selected.status} onChange={(e) => void setStatus(e.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></label><button onClick={() => void exportIncident()}><FileDown size={15} /> Export evidence</button></div>

        <section className="drawer-section"><div className="section-title"><Activity size={16} /><div><h3>Attack timeline</h3><span>How separate signals became one incident</span></div></div>
          <div className="timeline">{selected.alerts?.map((alert, index) => <article key={alert.alert_id}>
            <div className="timeline-dot">{index + 1}</div><time>{timeLabel(alert.window_start, selected.first_seen)}</time><h4>{pretty(alert.subtype)}</h4>
            <p>{pretty(alert.threat_type)} · {alert.detector_id}</p>
            {alert.dst_ip && <span className="route mono">{selected.src_ip} <ChevronRight size={10} /> {alert.dst_ip}</span>}
          </article>)}</div></section>

        <section className="drawer-section"><div className="section-title"><Database size={16} /><div><h3>Evidence by detector</h3><span>Observed value, threshold and plain-language reason</span></div></div>
          {selected.alerts?.map((alert) => <div className="evidence-group" key={alert.alert_id}>
            <div className="evidence-group-head"><div><b>{pretty(alert.subtype)}</b><span>{alert.detector_id}</span></div><span>{Math.round(alert.confidence * 100)}% confidence</span></div>
            <div className="evidence-grid">{alert.evidence.map((item) => <article className="evidence" key={`${alert.alert_id}-${item.name}`}><div><span>{pretty(item.name)}</span><strong>{item.observed}</strong></div><p>{item.explanation}</p><small>{item.comparison}</small></article>)}</div>
          </div>)}
          <div className="score-breakdown"><p className="eyebrow">Risk score breakdown</p><div className="factor-grid">{selected.scoring_factors.map((item) => <div key={item.name}><span>{pretty(item.name)}</span><b>+{item.observed}</b></div>)}</div></div>
        </section>

        <section className="drawer-section"><div className="section-title"><UserRoundCheck size={16} /><div><h3>Analyst decision</h3><span>Record a human-reviewed disposition</span></div></div>
          <div className="review-form"><input aria-label="Analyst name" value={analyst} onChange={(e) => setAnalyst(e.target.value)} placeholder="Analyst name" /><textarea aria-label="Investigation notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Investigation notes and evidence context" rows={3} /><div className="decision-row"><button className="danger-action" onClick={() => void submitFeedback("confirmed_malicious")}><ShieldAlert size={14} /> Malicious</button><button onClick={() => void submitFeedback("needs_review")}><Clock3 size={14} /> Needs review</button><button className="safe-action" onClick={() => void submitFeedback("benign")}><CheckCircle2 size={14} /> Benign</button></div></div>
          {!!selected.feedback?.length && <div className="feedback-log">{selected.feedback.map((item) => <article key={item.feedback_id}><b>{pretty(item.disposition)}</b><span>{item.analyst} · {timeLabel(item.timestamp, selected.first_seen)}</span><p>{item.notes || "No notes added."}</p></article>)}</div>}
        </section>
      </aside>
    </div>}
    {message && <button className="toast" onClick={() => setMessage("")}>{message}<X size={14} /></button>}
  </div>;
}

export default App;
