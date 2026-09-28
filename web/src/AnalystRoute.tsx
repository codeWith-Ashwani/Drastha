import { useMemo, useState } from "react";
import { Activity, ArrowRight, CircleAlert, Eye, Network, ShieldCheck } from "lucide-react";
import { ATTACKS, buildAttackAnalytics, type AnalystAlert, type AnalystIncident, type AttackId } from "./attackAnalytics";
import type { RunEvidence, RunSummary } from "./App";
import "./analyst.css";

type Props = {
  alerts: AnalystAlert[];
  incidents: AnalystIncident[];
  source: string;
  scope: string;
  loading: boolean;
  timelineAvailable: boolean;
  history: RunSummary[];
  selectedRunId: string | null;
  selectedRun: RunEvidence | null;
  hasMoreHistory: boolean;
  onSelectRun: (runId: string | null) => void;
  onLoadMore: () => void;
  onReview: (alert: AnalystAlert) => void;
};

const displayTime = (seconds: number) => seconds >= 946684800
  ? new Date(seconds * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })
  : `Capture +${Math.round(seconds)}s`;

export function AnalystRoute({ alerts, incidents, source, scope, loading, timelineAvailable, history, selectedRunId, selectedRun, hasMoreHistory, onSelectRun, onLoadMore, onReview }: Props) {
  const [selectedId, setSelectedId] = useState<AttackId>("distributed_syn");
  const analytics = useMemo(() => buildAttackAnalytics(alerts, incidents, 12, selectedRun ? {
    start: selectedRun.capture_start, end: selectedRun.capture_end,
  } : undefined), [alerts, incidents, selectedRun]);
  const selected = analytics.rows.find((row) => row.id === selectedId) ?? analytics.rows[0];
  const maxCount = Math.max(1, ...analytics.rows.map((row) => row.count));
  const maxBucket = Math.max(1, ...analytics.rows.flatMap((row) => row.buckets));
  const datedHistory = history.filter((run) => run.analysed_at !== null).slice().reverse();
  const maxRunFindings = Math.max(1, ...datedHistory.map((run) => run.findings));
  const legacyRuns = history.length - datedHistory.length;
  return <div className="analyst-route" id="analyst-top">
    <section className="analyst-intro">
      <div><p className="eyebrow">SOC analyst / visual intelligence</p><h1>Threat landscape</h1>
        <p>See where the passive detectors found suspicious behaviour, how it changed over time, and the actual measurements behind each finding.</p></div>
      <span className="analyst-source"><Activity size={15} />{source}</span>
    </section>
    <p className="analyst-scope"><ShieldCheck size={16} />{scope} Charts show detector findings, not confirmed attacks. Review evidence and operational context before concluding.</p>
    <section className="analyst-panel analyst-history" aria-labelledby="run-history-heading">
      <div className="analyst-panel-head"><div><p className="eyebrow">Current and past attacks</p><h2 id="run-history-heading">Analysis history</h2></div><span>{history.length} saved runs loaded</span></div>
      <div className="analyst-history-controls"><label htmlFor="analyst-run-select">View timeline for</label><select id="analyst-run-select" value={selectedRunId ?? "all"} onChange={(event) => onSelectRun(event.target.value === "all" ? null : event.target.value)}>
        <option value="all">All stored incidents · mixed runs</option>
        {history.map((run) => <option key={run.run_id} value={run.run_id}>{run.filename} · {run.analysed_at ? new Date(run.analysed_at * 1000).toLocaleString() : "legacy · analysis time unknown"} · {run.findings} findings</option>)}
      </select>{hasMoreHistory && <button type="button" className="secondary" onClick={onLoadMore}>Load older runs</button>}</div>
      <div className="analyst-clock-line"><span><b>Analysed:</b> {selectedRun?.analysed_at ? new Date(selectedRun.analysed_at * 1000).toLocaleString() : selectedRunId ? "Not recorded for this legacy run" : "Select a saved run"}</span><span><b>Traffic captured:</b> {selectedRun?.capture_start != null && selectedRun.capture_end != null ? `${displayTime(selectedRun.capture_start)} – ${displayTime(selectedRun.capture_end)}` : "Window unavailable"}</span></div>
      {datedHistory.length > 0 && <div className="analyst-history-chart" aria-label="Findings by saved analysis run"><div className="analyst-history-bars">{datedHistory.map((run) => <button type="button" key={run.run_id} className={selectedRunId === run.run_id ? "is-selected" : ""} style={{ height: `${Math.max(18, run.findings / maxRunFindings * 100)}%` }} onClick={() => onSelectRun(run.run_id)} title={`${run.filename}: ${run.findings} findings, analysed ${new Date(run.analysed_at! * 1000).toLocaleString()}`} aria-label={`Open ${run.filename}, ${run.findings} findings`}><span>{run.findings}</span></button>)}</div><div className="analyst-history-axis"><span>{new Date(datedHistory[0].analysed_at! * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}</span><span>{new Date(datedHistory[datedHistory.length - 1].analysed_at! * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}</span></div></div>}
      <p className="analyst-caption">This history graph uses the time Drastha analysed each run. The attack timeline below uses original traffic capture times. {legacyRuns > 0 ? `${legacyRuns} legacy run${legacyRuns === 1 ? " has" : "s have"} no recorded analysis time; browse them in the selector, but they cannot be placed on this time axis.` : ""}</p>
    </section>
    {loading && <p className="analyst-loading"><Activity className="spin" size={16} />Loading current incident evidence…</p>}
    <section className="analyst-kpis" aria-label="Attack overview">
      <article><span>Labelled findings</span><strong>{analytics.totalAlerts}</strong><small>Alert records in this view</small></article>
      <article><span>Behaviours observed</span><strong>{analytics.detectedBehaviours}<em> / {ATTACKS.length}</em></strong><small>Detector categories with evidence</small></article>
      <article><span>Correlated incidents</span><strong>{analytics.incidentCount}</strong><small>Distinct incident identities</small></article>
      <article><span>Visibility</span><strong className="analyst-kpi-word">Passive</strong><small>No active probe or payload decryption</small></article>
    </section>
    <div className="analyst-grid">
      <section className="analyst-panel analyst-distribution" aria-labelledby="distribution-heading">
        <div className="analyst-panel-head"><div><p className="eyebrow">Detection mix</p><h2 id="distribution-heading">Findings by attack behaviour</h2></div><span>Alert count</span></div>
        <div className="analyst-bars">{analytics.rows.map((row) => <button type="button" key={row.id} className={`analyst-bar-row ${selected.id === row.id ? "is-selected" : ""}`} onClick={() => setSelectedId(row.id)} aria-label={`${row.title}: ${row.count} findings. Show details.`}>
          <span className="analyst-bar-name">{row.title}</span><span className="analyst-bar-track"><span style={{ width: `${row.count ? Math.max(5, row.count / maxCount * 100) : 0}%` }} /></span><b>{row.count}</b>
        </button>)}</div>
        <p className="analyst-caption">One alert is counted in exactly one behaviour. Zero means none observed in this data source, not proof that the network is safe.</p>
      </section>
      <section className="analyst-panel analyst-timeline" aria-labelledby="timeline-heading">
        <div className="analyst-panel-head"><div><p className="eyebrow">When it appeared</p><h2 id="timeline-heading">Detection timeline</h2></div><span>12 equal time buckets</span></div>
        {!timelineAvailable ? <div className="analyst-no-data"><Network size={24} /><b>Timeline needs one replay or stream</b><span>The stored queue combines runs that may use different clocks. Select a saved run, upload a replay, or start a stream for a truthful time chart.</span></div> : analytics.totalAlerts === 0 ? <div className="analyst-no-data"><Network size={24} /><b>No alert timeline yet</b><span>Run or upload traffic to populate measured detections.</span></div> : <>
          <div className="analyst-heatmap" role="img" aria-label="Alert counts by attack behaviour across twelve time buckets">
            {analytics.rows.map((row) => <div key={row.id} className="analyst-heat-row"><span title={row.title}>{row.title}</span><div>{row.buckets.map((count, index) => <i key={index} style={{ opacity: count ? .24 + .76 * count / maxBucket : undefined }} className={count ? "has-detection" : ""} title={`${row.title}: ${count} findings in bucket ${index + 1}`} />)}</div></div>)}
          </div><div className="analyst-time-axis"><span>{displayTime(analytics.start)}</span><span>{displayTime(analytics.end)}</span></div>
          <p className="analyst-caption">Buckets cover the full recorded capture window when available and use alert window start times. Colour intensity represents count, not severity or confidence.</p>
        </>}
      </section>
    </div>
    <section className="analyst-panel analyst-catalogue" aria-labelledby="catalogue-heading">
      <div className="analyst-panel-head"><div><p className="eyebrow">Threat coverage</p><h2 id="catalogue-heading">Explore each attack type</h2></div><span>Choose a behaviour</span></div>
      <div className="analyst-attack-grid">{analytics.rows.map((row) => <button type="button" key={row.id} className={`analyst-attack-card ${selected.id === row.id ? "is-selected" : ""}`} onClick={() => setSelectedId(row.id)} aria-pressed={selected.id === row.id}>
        <span className="analyst-attack-meta"><span>{row.family}</span><span className={row.count ? "observed" : "not-observed"}>{row.count ? `${row.count} finding${row.count === 1 ? "" : "s"}` : "0 observed"}</span></span>
        <b>{row.title}</b><small>{row.description}</small><span className="analyst-attack-bottom">{row.averageConfidence === null ? "No confidence score" : `${row.averageConfidence}% mean detector confidence`}<ArrowRight size={15} /></span>
      </button>)}</div>
    </section>
    <section className="analyst-panel analyst-drilldown" aria-live="polite" aria-labelledby="drilldown-heading">
      <div className="analyst-panel-head"><div><p className="eyebrow">Evidence lens / {selected.family}</p><h2 id="drilldown-heading">{selected.title}</h2></div><span>{selected.count} findings · {selected.incidents} incidents</span></div>
      <p className="analyst-description">{selected.description}</p>
      <div className="analyst-explainer"><div><span>Detector looks for</span><b>{selected.signal}</b></div><div><span>Interpretation limit</span><b>{selected.caution}</b></div></div>
      {selected.count === 0 ? <div className="analyst-no-data"><CircleAlert size={21} /><b>No finding for this behaviour in the selected source</b><span>Insufficient coverage or evidence is not a benign verdict.</span></div> : <div className="analyst-finding-grid">{selected.alerts.map((alert) => <article key={alert.alert_id} className="analyst-finding">
        <div className="analyst-finding-top"><span className={`severity severity-${alert.severity}`}>{alert.severity}</span><strong>{Math.round(alert.confidence * 100)}% confidence</strong></div>
        <h3>{alert.threat_class || selected.title}</h3><p className="analyst-endpoints">{alert.src_ip} → {alert.dst_ip || "multiple destinations"}</p>
        <div className="analyst-finding-meta"><span>Detector {alert.detector_id}</span><span>{displayTime(alert.window_start)}</span><span>{alert.flow_ids?.length ?? 0} flow IDs</span></div>
        <div className="analyst-measures">{alert.evidence.slice(0, 4).map((item, index) => <div key={`${item.name}-${index}`}><span>{item.name.replaceAll("_", " ")}</span><b>{String(item.observed)}</b><small>{item.explanation}</small></div>)}</div>
        {alert.limitations[0] && <p className="analyst-limit">{alert.limitations[0]}</p>}
        <button type="button" className="secondary" onClick={() => onReview(alert)}><Eye size={15} />Review full incident</button>
      </article>)}</div>}
    </section>
  </div>;
}
