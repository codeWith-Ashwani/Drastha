export type OverallRiskData = {
  score: number;
  severity: string;
  incident_count: number;
  distinct_threat_types: number;
  affected_sources: number;
  dominant_incident_id?: string | null;
  dominant_threat_types: string[];
  scoring_factors: Array<{
    name: string;
    observed: number | string;
    comparison: string;
    explanation: string;
  }>;
  assessment: string;
  uncertainty: string;
};

export function OverallRisk({ value, label }: {
  value: OverallRiskData;
  label: (value: string) => string;
}) {
  const heading = value.severity === "none"
    ? "No aggregate incident risk scored"
    : `${label(value.severity)} overall investigation priority`;
  return <section className={`overall-risk overall-risk-${value.severity}`} aria-label="Overall replay risk">
    <div className="overall-risk-score"><b>{value.score}</b><span>/100</span></div>
    <div className="overall-risk-content">
      <p className="eyebrow">Overall replay risk</p>
      <h3>{heading}</h3>
      <p>{value.assessment}</p>
      {value.scoring_factors.length > 0 && <div className="overall-risk-factors">
        {value.scoring_factors.map((factor) => <span key={factor.name}>
          {label(factor.name)} <b>+{factor.observed}</b>
        </span>)}
      </div>}
      <small>{value.uncertainty}</small>
    </div>
  </section>;
}
