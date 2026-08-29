import { useEffect, useMemo, useState } from "react";
import {
  Activity, ArrowDownToLine, CheckCircle2, ChevronRight, CircleDot,
  Clock3, Database, FileDown, Filter, Radar, RefreshCw, Search, ShieldAlert,
  ShieldCheck, Signal, UserRoundCheck, X,
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

const API = "/api";
const pretty = (value: string) => value.replaceAll("_", " ");
const timeLabel = (value: number) => new Date(value * 1000).toLocaleString([], {
  day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
});

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
    <strong>{value}</strong><small>{note}</small>
  </article>;
}

function SeverityPill({ value }: { value: string }) {
  return <span className={`pill severity-${value}`}>{value}<CircleDot size={11} /></span>;
}

function EmptyState({ onLoad }: { onLoad: () => void }) {
  return <div className="empty-state">
    <Radar size={38} /><h2>No incident data yet</h2>
    <p>Load the offline demonstration dataset to explore the analyst workflow.</p>
    <button className="primary" onClick={onLoad}><ArrowDownToLine size={16} /> Load demo data</button>
  </div>;
}

function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
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
      const [queue, summary] = await Promise.all([
        api<Incident[]>("/incidents"), api<Metrics>("/metrics"),
      ]);
      setIncidents(queue); setMetrics(summary);
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

  const openIncident = async (id: string) => {
    try { setSelected(await api<Incident>(`/incidents/${id}`)); }
    catch (error) { setMessage((error as Error).message); }
  };
  const loadDemo = async () => {
    setMessage("Loading demonstration data…");
    try { await api("/demo/load", { method: "POST" }); setMessage("Demo data loaded."); await refresh(false); }
    catch (error) { setMessage((error as Error).message); }
  };
  const setStatus = async (status: string) => {
    if (!selected) return;
    await api(`/incidents/${selected.incident_id}/status`, {
      method: "PATCH", body: JSON.stringify({ status }),
    });
    setMessage(`Incident marked ${pretty(status)}.`); await refresh();
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
        <div><b>AegisFlow</b><span>Analyst Console</span></div></div>
      <div className="system-state"><Signal size={14} /><span>Passive sensor</span><b>ONLINE</b></div>
      <button className="icon-button" onClick={() => void refresh()} aria-label="Refresh queue"><RefreshCw size={17} /></button>
    </header>

    <main>
      <section className="page-heading">
        <div><p className="eyebrow">Operations / Incident queue</p><h1>Threat operations overview</h1>
          <p>Prioritized signals from the one-way monitoring pipeline.</p></div>
        <div className="freshness"><Clock3 size={15} /><span>Snapshot</span><b>just now</b></div>
      </section>

      <section className="metrics-grid">
        <MetricCard label="Active incidents" value={metrics?.active_incidents ?? "—"} note="Requires analyst attention" icon={ShieldAlert} tone="coral" />
        <MetricCard label="Critical" value={metrics?.critical_incidents ?? "—"} note="Highest-priority cases" icon={Activity} tone="amber" />
        <MetricCard label="Average risk" value={metrics ? `${metrics.average_risk_score}/100` : "—"} note="Policy score, not confidence" icon={Radar} />
        <MetricCard label="Reviewed" value={metrics?.feedback_records ?? "—"} note="Analyst decisions retained" icon={UserRoundCheck} tone="blue" />
      </section>

      <section className="workspace">
        <div className="queue-panel">
          <div className="panel-head"><div><h2>Incident queue</h2><span>{filtered.length} prioritized result{filtered.length === 1 ? "" : "s"}</span></div>
            <div className="filters"><label className="search"><Search size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="IP, ID or threat" /></label>
              <label className="select"><Filter size={14} /><select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="all">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></div></div>

          {loading ? <div className="loading"><RefreshCw className="spin" /> Synchronizing incident queue…</div> :
            incidents.length === 0 ? <EmptyState onLoad={loadDemo} /> :
            <div className="table-wrap"><table><thead><tr><th>Risk</th><th>Source</th><th>Threat story</th><th>Severity</th><th>Status</th><th>Last seen</th><th></th></tr></thead>
              <tbody>{filtered.map((item) => <tr key={item.incident_id} onClick={() => void openIncident(item.incident_id)}>
                <td><div className={`risk risk-${item.severity}`}>{item.risk_score}</div></td>
                <td><b className="mono">{item.src_ip}</b><small className="mono">{item.incident_id.slice(0, 8)}</small></td>
                <td><div className="threat-list">{item.threat_types.map((threat) => <span key={threat}>{pretty(threat)}</span>)}</div><small>{item.detector_ids.length} contributing detector{item.detector_ids.length === 1 ? "" : "s"}</small></td>
                <td><SeverityPill value={item.severity} /></td><td><span className={`status status-${item.status}`}>{pretty(item.status)}</span></td>
                <td className="time">{timeLabel(item.last_seen)}</td><td><ChevronRight size={16} /></td>
              </tr>)}</tbody></table></div>}
        </div>
      </section>
    </main>

    {selected && <div className="drawer-backdrop" onMouseDown={(e) => { if (e.currentTarget === e.target) setSelected(null); }}>
      <aside className="drawer" aria-label="Incident evidence drawer">
        <div className="drawer-head"><div><p className="eyebrow">Incident investigation</p><h2>{selected.src_ip}</h2><span className="mono">{selected.incident_id}</span></div><button className="icon-button" onClick={() => setSelected(null)}><X size={19} /></button></div>
        <div className="incident-summary"><div className={`score score-${selected.severity}`}><strong>{selected.risk_score}</strong><span>risk score</span></div>
          <div><SeverityPill value={selected.severity} /><p><b>{Math.round(selected.confidence * 100)}%</b> detector confidence</p><small>Severity policy and confidence are intentionally separate.</small></div></div>
        <div className="action-row"><select value={selected.status} onChange={(e) => void setStatus(e.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select><button onClick={() => void exportIncident()}><FileDown size={15} /> Export JSON</button></div>

        <section className="drawer-section"><div className="section-title"><Activity size={16} /><h3>Attack timeline</h3></div>
          <div className="timeline">{selected.alerts?.map((alert) => <article key={alert.alert_id}>
            <div className="timeline-dot"></div><time>{timeLabel(alert.window_start)}</time><h4>{pretty(alert.subtype)}</h4>
            <p>{pretty(alert.threat_type)} · {alert.detector_id}</p>
            {alert.dst_ip && <span className="route mono">{selected.src_ip} → {alert.dst_ip}</span>}
          </article>)}</div></section>

        <section className="drawer-section"><div className="section-title"><Database size={16} /><h3>Evidence</h3></div>
          {selected.alerts?.flatMap((alert) => alert.evidence.map((item) => <article className="evidence" key={`${alert.alert_id}-${item.name}`}><div><span>{pretty(item.name)}</span><strong>{item.observed}</strong></div><p>{item.explanation}</p><small>{item.comparison}</small></article>))}
          <div className="factor-grid">{selected.scoring_factors.map((item) => <div key={item.name}><span>{pretty(item.name)}</span><b>+{item.observed}</b></div>)}</div>
        </section>

        <section className="drawer-section"><div className="section-title"><UserRoundCheck size={16} /><h3>Analyst decision</h3></div>
          <div className="review-form"><input value={analyst} onChange={(e) => setAnalyst(e.target.value)} placeholder="Analyst name" /><textarea value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Investigation notes and evidence context" rows={3} /><div className="decision-row"><button onClick={() => void submitFeedback("confirmed_malicious")}><ShieldAlert size={14} /> Malicious</button><button onClick={() => void submitFeedback("needs_review")}><Clock3 size={14} /> Review</button><button onClick={() => void submitFeedback("benign")}><CheckCircle2 size={14} /> Benign</button></div></div>
          {!!selected.feedback?.length && <div className="feedback-log">{selected.feedback.map((item) => <article key={item.feedback_id}><b>{pretty(item.disposition)}</b><span>{item.analyst} · {timeLabel(item.timestamp)}</span><p>{item.notes || "No notes added."}</p></article>)}</div>}
        </section>
      </aside>
    </div>}
    {message && <button className="toast" onClick={() => setMessage("")}>{message}<X size={14} /></button>}
  </div>;
}

export default App;
