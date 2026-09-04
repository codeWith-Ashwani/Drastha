export type IncidentConclusionData = {
  assessment: string;
  likely_objective: string;
  attack_stage: string;
  potential_impact: string;
  confidence_basis: string[];
  uncertainty: string;
  inference_basis: string;
};

export function IncidentConclusion({ value }: { value?: IncidentConclusionData | null }) {
  if (!value) return <section className="detail-section conclusion-section">
    <div className="conclusion-heading"><div><p className="eyebrow">Analyst conclusion</p>
      <h3>Conclusion not recorded</h3></div><span>Legacy incident</span></div>
    <p className="scope-note">Replay this source to create an evidence-backed incident conclusion with the current analysis engine.</p>
  </section>;

  return <section className="detail-section conclusion-section">
    <div className="conclusion-heading"><div><p className="eyebrow">Analyst conclusion</p>
      <h3>What this incident most likely means</h3></div><span>Inferred · passive metadata</span></div>
    <p className="conclusion-assessment">{value.assessment}</p>
    <div className="conclusion-grid">
      <div><span>Likely objective</span><b>{value.likely_objective}</b></div>
      <div><span>Attack stage</span><b>{value.attack_stage}</b></div>
      <div><span>Potential impact</span><b>{value.potential_impact}</b></div>
    </div>
    <div className="conclusion-basis"><h4>Evidence behind this conclusion</h4><ul>
      {value.confidence_basis.map((item, index) => <li key={index}>{item}</li>)}
    </ul></div>
    <p className="conclusion-limit"><b>Analytical limit:</b> {value.uncertainty}</p>
  </section>;
}
