import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";
import { ATTACKS, attackId, buildAttackAnalytics } from "../src/attackAnalytics.ts";
const alert = (subtype, index, threat_type = "") => ({
  alert_id: `alert-${index}`, subtype, threat_type, confidence: .8,
  severity: "high", window_start: 100 + index * 10, window_end: 101 + index * 10,
  src_ip: "192.0.2.1", detector_id: "test", evidence: [], limitations: [],
});

test("all named attack behaviours map to one visual category each", () => {
  const subtypes = [
    "syn_flood", "distributed_source_syn_flood", "udp_reflection_amplification",
    "vertical_port_scan", "periodic_beacon", "dga_like_domain", "dns_tunnelling",
    "encrypted_session_metadata_anomaly", "outbound_volume_anomaly",
  ];
  const alerts = subtypes.map((name, index) => alert(name, index));
  const incidents = alerts.map((item, index) => ({ incident_id: `incident-${index}`, alert_ids: [item.alert_id], risk_score: 70 }));
  const analytics = buildAttackAnalytics(alerts, incidents);
  assert.equal(ATTACKS.length, 9);
  assert.equal(analytics.totalAlerts, 9);
  assert.equal(analytics.detectedBehaviours, 9);
  assert.equal(analytics.incidentCount, 9);
  assert.ok(analytics.rows.every((row) => row.count === 1));
  assert.ok(analytics.rows.every((row) => row.buckets.reduce((sum, count) => sum + count, 0) === row.count));
  assert.equal(attackId(alert("suspected_spoofed_source_flood", 10)), "distributed_syn");
});

test("empty evidence stays zero rather than becoming demo findings", () => {
  const analytics = buildAttackAnalytics([], []);
  assert.equal(analytics.totalAlerts, 0);
  assert.equal(analytics.detectedBehaviours, 0);
  assert.equal(analytics.incidentCount, 0);
  assert.equal(analytics.rows.length, 9);
  assert.ok(analytics.rows.every((row) => row.count === 0 && row.averageConfidence === null && row.highestRisk === null));
});

test("alerts have one owner, confidence is descriptive, and unknown subtypes remain visible", () => {
  const alerts = [alert("periodic_beacon", 0), alert("periodic_beacon", 1), alert("new_detector", 2)];
  const incidents = [{ incident_id: "i-1", alert_ids: ["alert-0", "alert-1"], risk_score: 73 }];
  const analytics = buildAttackAnalytics(alerts, incidents);
  const c2 = analytics.rows.find((row) => row.id === "c2");
  assert.equal(c2.count, 2);
  assert.equal(c2.incidents, 1);
  assert.equal(c2.averageConfidence, 80);
  assert.equal(c2.highestRisk, 73);
  assert.equal(analytics.rows.find((row) => row.id === "other").count, 1);
  assert.equal(analytics.rows.reduce((sum, row) => sum + row.count, 0), alerts.length);
});

test("timeline covers the whole capture, not only the first and last finding", () => {
  const analytics = buildAttackAnalytics([alert("periodic_beacon", 0)], [], 10, { start: 0, end: 1000 });
  assert.equal(analytics.start, 0);
  assert.equal(analytics.end, 1000);
  assert.equal(analytics.rows.find((row) => row.id === "c2").buckets[1], 1);
});

test("SOC route reuses run-scoped replay evidence and keeps the queue scope explicit", () => {
  const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const page = readFileSync(new URL("../src/AnalystRoute.tsx", import.meta.url), "utf8");
  const styles = readFileSync(new URL("../src/analyst.css", import.meta.url), "utf8");
  assert.match(app, /href="\/analyst"/);
  assert.match(app, /routeFromPath/);
  assert.match(app, /activeAnalystRun\?\.alerts/);
  assert.match(app, /setLatestRun\(result\); setAnalystRunId\(result\.run_id\)/);
  assert.match(app, /queueItems = latestRun && !showAllQueue \? latestRun\.incidents : incidents/);
  assert.match(app, /Stored queue may include incidents from different runs/);
  assert.match(app, /openReplayEvidence\(activeAnalystRun, activeAnalystRun\.incidents\.find/);
  assert.match(app, /Latest analysis:/);
  assert.match(app, /Analysed \{timeLabel\(latestRun\.analysed_at\)\}/);
  assert.match(app, /Captured \{timeLabel\(item\.last_seen\)\}/);
  assert.match(app, /expectedAlertIds && \[\.\.\.incident\.alert_ids\]\.sort\(\)\.join/);
  assert.match(page, /Charts show detector findings, not confirmed attacks/);
  assert.match(page, /The stored queue combines runs that may use different clocks/);
  assert.match(page, /Analysis history/);
  assert.match(page, /legacy .*analysis time unknown/);
  assert.match(app, /timelineAvailable=\{Boolean\(liveAnalystStream \|\| activeAnalystRun\)\}/);
  assert.match(page, /0 observed/);
  assert.match(page, /Review full incident/);
  const base = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");
  const root = base.match(/:root\s*\{([^}]+)\}/)[1];
  const tokens = new Set([...root.matchAll(/(--[\w-]+):\s*[^;]+;/g)].map((match) => match[1]));
  for (const match of styles.matchAll(/var\((--[\w-]+)/g)) assert.ok(tokens.has(match[1]), `Undefined analyst token ${match[1]}`);
});

test("historical run view renders its own capture timeline and evidence", async () => {
  const server = await createServer({ root: fileURLToPath(new URL("..", import.meta.url)),
    server: { middlewareMode: true, hmr: false, watch: null } });
  let page;
  try { page = await server.ssrLoadModule("/src/AnalystRoute.tsx"); }
  finally { await server.close(); }
  const old = alert("distributed_source_syn_flood", 0);
  old.evidence = [{ name: "mean_interval_seconds", observed: "3.0", comparison: "< 5", explanation: "Old-run-only timing" }];
  const run = { run_id: "old-run", filename: "old.jsonl", analysed_at: 1_800_000_000,
    capture_start: 0, capture_end: 1000, alerts: [old], incidents: [{ incident_id: "old-incident", alert_ids: [old.alert_id], risk_score: 72 }] };
  const history = [{ run_id: "new-run", filename: "new.jsonl", analysed_at: 1_800_100_000, findings: 4 },
    { run_id: "old-run", filename: "old.jsonl", analysed_at: 1_800_000_000, findings: 1 }];
  const html = renderToStaticMarkup(createElement(page.AnalystRoute, {
    alerts: run.alerts, incidents: run.incidents, source: "Saved run · old.jsonl", scope: "Only this run.",
    loading: false, timelineAvailable: true, history, selectedRunId: run.run_id, selectedRun: run,
    hasMoreHistory: false, onSelectRun() {}, onLoadMore() {}, onReview() {},
  }));
  assert.match(html, /Analysis history/);
  assert.match(html, /Traffic captured:/);
  assert.match(html, /Old-run-only timing/);
  assert.match(html, /1<\/strong>/);
  assert.match(html, /new\.jsonl/);
  assert.doesNotMatch(html, /Timeline needs one replay or stream/);
});
