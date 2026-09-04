import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

const server = await createServer({
  root: fileURLToPath(new URL("..", import.meta.url)),
  server: { middlewareMode: true, hmr: false, watch: null },
});
let component;
try { component = await server.ssrLoadModule("/src/ReplayEvidence.tsx"); }
finally { await server.close(); }
const fixture = (runId, threats = ["data_exfiltration", "reconnaissance", "dns_threat"]) => ({
  run_id: runId, filename: runId + ".json", quality: { status: "healthy" },
  overall_risk: {
    score: threats.length ? 82 : 0, severity: threats.length ? "critical" : "none",
    incident_count: threats.length, distinct_threat_types: threats.length,
    affected_sources: threats.length, dominant_incident_id: threats.length ? "i0" : null,
    dominant_threat_types: threats.slice(0, 1),
    scoring_factors: threats.length ? [
      { name: "dominant_incident_risk", observed: 60, comparison: "base", explanation: "Anchor" },
      { name: "incident_breadth_bonus", observed: 6, comparison: "capped", explanation: "Breadth" },
      { name: "threat_diversity_bonus", observed: 6, comparison: "capped", explanation: "Diversity" },
    ] : [],
    assessment: threats.length ? "Multiple incidents require priority review." : "No incident was produced.",
    uncertainty: "This is not an attack probability and does not prove coordination.",
  },
  alerts: threats.map((threat, index) => ({
    alert_id: "a" + index, threat_class: threat, subtype: threat, severity: "high", confidence: .9,
    src_ip: "192.0.2." + index, dst_ip: "198.51.100.1",
    evidence: [{ name: "measured_feature", observed: `${runId}-value-${index}`, comparison: "> 4", explanation: "Measured evidence" }],
    limitations: ["Not proof of malicious intent", "Metadata only"],
  })),
  incidents: threats.map((threat, index) => ({
    incident_id: "i" + index, alert_ids: ["a" + index], threat_types: [threat], src_ip: "192.0.2." + index,
    risk_score: 60 - index * 10, severity: "high", confidence: .9,
    scoring_factors: [{ name: "threat_weight_total", observed: 40, explanation: "Priority policy" }],
    conclusion: {
      assessment: `Assessment for ${threat}`,
      likely_objective: `Objective for ${threat}`,
      attack_stage: `Stage for ${threat}`,
      potential_impact: `Impact for ${threat}`,
      confidence_basis: [`Basis for ${threat}`],
      uncertainty: "Passive metadata cannot prove actual intent.",
      inference_basis: "passive_metadata_only",
    },
  })),
});
const render = (run, initialIncidentId) => renderToStaticMarkup(createElement(component.ReplayEvidence, {
  run, initialIncidentId, onClose() {}, label: (value) => value,
}));

test("full evidence renders every incident, not only the highest-risk exfiltration", () => {
  const html = render(fixture("mixed"));
  for (const threat of ["data_exfiltration", "reconnaissance", "dns_threat"]) assert.ok(html.includes(threat));
  assert.equal((html.match(/data-incident-id=/g) ?? []).length, 3);
  assert.match(html, /mixed.json/);
  assert.match(html, /Run mixed/);
  assert.match(html, /All incidents \(3\)/);
  assert.match(html, /Metadata only/);
  assert.match(html, /What this incident most likely means/);
  assert.match(html, /Objective for data_exfiltration/);
  assert.match(html, /Passive metadata cannot prove actual intent/);
  assert.match(html, /Supporting measurements/);
  assert.match(html, /Overall replay risk/);
  assert.match(html, /82/);
  assert.match(html, /not an attack probability/);
});

test("per-finding review renders that incident's complete evidence", () => {
  const html = render(fixture("mixed"), "i1");
  assert.match(html, /data-incident-id="i1"/);
  assert.doesNotMatch(html, /data-incident-id="i0"/);
  assert.match(html, /mixed-value-1/);
  assert.doesNotMatch(html, /mixed-value-0/);
});

test("same identities in different runs do not leak another run's evidence", () => {
  const old = fixture("old", ["data_exfiltration"]);
  const current = fixture("current", ["reconnaissance"]);
  const saved = JSON.stringify(old);
  assert.equal(component.replayIncidents(old)[0].alerts[0].evidence[0].observed, "old-value-0");
  assert.equal(component.replayIncidents(current)[0].alerts[0].evidence[0].observed, "current-value-0");
  assert.match(render(current), /current-value-0/);
  assert.doesNotMatch(render(current), /old-value|data_exfiltration/);
  assert.equal(JSON.stringify(old), saved);
});

test("benign replay cannot fall back to a previous attack", () => {
  const html = render(fixture("benign", []));
  assert.match(html, /No configured threat finding/);
  assert.doesNotMatch(html, /data-incident-id=/);
  assert.match(html, /benign.json/);
});

test("run join excludes unrelated alerts even if they are present in the run", () => {
  const run = fixture("mixed");
  const joined = component.replayIncidents(run);
  for (const incident of joined) assert.deepEqual(incident.alerts.map((alert) => alert.alert_id), incident.alert_ids);
});

test("upload button uses run snapshot and incident navigation invalidates stale requests", () => {
  const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(app, /onClick=\{\(\) => openReplayEvidence\(uploadResult\)\}/);
  assert.doesNotMatch(app, /openIncident\(uploadResult.top_incident_id/);
  assert.match(app, /request === detailRequest.current/);
  assert.match(app, /const closeEvidence = \(\) => \{\s*detailRequest.current \+= 1;/);
  assert.match(app, /closeEvidence\(\); setStream\(null\);/);
  assert.match(app, /Review this incident/);
  assert.match(app, /<IncidentConclusion value=\{selected\.conclusion\}/);
  assert.match(app, /Detection timeline/);
  assert.match(app, /Supporting measurements/);
});
