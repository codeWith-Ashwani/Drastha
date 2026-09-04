import { useEffect, useRef, useState } from "react";
import { Download, X } from "lucide-react";
import type { UploadResult } from "./App";
import { IncidentConclusion } from "./IncidentConclusion";
import { OverallRisk } from "./OverallRisk";

// Join only within this completed run. Never hydrate historical evidence from
// the mutable global incident queue, whose deterministic IDs can be reused.
export function replayIncidents(run: UploadResult) {
  const alerts = new Map(run.alerts.map((alert) => [alert.alert_id, alert]));
  return run.incidents.map((incident) => ({ ...incident,
    alerts: incident.alert_ids.flatMap((id) => alerts.has(id) ? [alerts.get(id)!] : []),
  }));
}

export function ReplayEvidence({ run, initialIncidentId, onClose, label }: {
  run: UploadResult; initialIncidentId?: string; onClose: () => void;
  label: (value: string) => string;
}) {
  const [filter, setFilter] = useState(initialIncidentId ?? "all");
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    const previous = document.activeElement as HTMLElement | null;
    element?.showModal();
    return () => { element?.close(); previous?.focus(); };
  }, []);
  const incidents = replayIncidents(run);
  const visible = filter === "all" ? incidents : incidents.filter((item) => item.incident_id === filter);
  const exportRun = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(run, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = `drastha-replay-${run.run_id}.json`; link.click();
    URL.revokeObjectURL(url);
  };
  return <dialog ref={dialog} className="replay-evidence-dialog" aria-labelledby="replay-evidence-title"
    onCancel={onClose}>
    <div className="drawer-head"><div><p className="eyebrow">Completed replay evidence</p>
      <h2 id="replay-evidence-title">{run.filename}</h2><span>Run {run.run_id}</span>
    </div><button aria-label="Close replay evidence" onClick={onClose}><X size={19} /></button></div>
    <p className="scope-note">Evidence from this replay only. The investigation queue holds the latest analyst state and can include other replays.</p>
    <div className="result-facts"><span><b>{run.alerts.length}</b> findings</span>
      <span><b>{incidents.length}</b> incidents</span><span><b>{run.quality.status}</b> data quality</span></div>
    {run.overall_risk && <OverallRisk value={run.overall_risk} label={label} />}
    <div className="drawer-actions"><label><span>Incident evidence</span>
      <select aria-label="Select replay incident" value={filter} onChange={(event) => setFilter(event.target.value)}>
        <option value="all">All incidents ({incidents.length})</option>
        {incidents.map((item) => <option key={item.incident_id} value={item.incident_id}>
          {item.threat_types.map(label).join(" + ")} · {item.src_ip} · {item.incident_id}
        </option>)}
      </select></label><button onClick={exportRun}><Download size={14} />Export replay evidence</button></div>
    {visible.length === 0 && <p>No configured threat finding in this replay. Review quality and feature coverage; this is not a guarantee of safety.</p>}
    {visible.map((incident) => <section className="detail-section" key={incident.incident_id} data-incident-id={incident.incident_id}>
      <h3>{incident.threat_types.map(label).join(" + ")}</h3>
      <p className="route">{incident.src_ip} · #{incident.incident_id}</p>
      <div className="incident-verdict"><div className={`risk risk-${incident.severity}`}><b>{incident.risk_score}</b><span>risk</span></div>
        <div><b>{incident.severity} priority</b><span>{Math.round(incident.confidence * 100)}% detector confidence</span>
          <small>Risk is investigation priority, not certainty.</small></div></div>
      <IncidentConclusion value={incident.conclusion} />
      <h4>Supporting measurements</h4>
      {incident.alerts.map((alert) => <article className="detail-finding" key={alert.alert_id}>
        <div><b>{alert.threat_class || label(alert.subtype)}</b><span>{Math.round(alert.confidence * 100)}% confidence</span></div>
        <p className="route">{alert.src_ip} → {alert.dst_ip || "multiple destinations"}</p>
        <p className="scope-note">Detector {alert.detector_id} · alert {alert.alert_id} · window {alert.window_start}–{alert.window_end} · {alert.flow_ids?.length ?? 0} contributing flow IDs</p>
        <div className="evidence-list">{alert.evidence.map((item, index) => <div key={`${item.name}-${index}`}>
          <span>{label(item.name)}</span><b>{item.observed}</b><small>{item.explanation}</small><em>{item.comparison}</em>
        </div>)}</div>
        {alert.limitations.map((item, index) => <p key={index} className="caveat">{item}</p>)}
      </article>)}
      <h4>Priority score</h4><div className="score-list">{incident.scoring_factors.map((item) => <div key={item.name}>
        <span>{label(item.name)}</span><b>+{item.observed}</b><small>{item.explanation}</small>
      </div>)}</div>
    </section>)}
  </dialog>;
}
