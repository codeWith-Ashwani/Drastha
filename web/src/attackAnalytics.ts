export type AnalystEvidence = {
  name: string; observed: number | string; comparison: string; explanation: string;
};

export type AnalystAlert = {
  alert_id: string; subtype: string; threat_type: string; threat_class?: string;
  confidence: number; severity: string; window_start: number; window_end: number;
  src_ip: string; dst_ip?: string; detector_id: string; flow_ids?: string[];
  evidence: AnalystEvidence[]; limitations: string[];
};

export type AnalystIncident = {
  incident_id: string; alert_ids: string[]; risk_score: number;
  src_ip: string; severity: string; conclusion?: unknown;
};

export const ATTACKS = [
  { id: "syn_flood", title: "SYN flood", family: "DDoS", description: "Many incomplete TCP handshakes concentrated on a service.", signal: "SYN rate · incomplete connections · target concentration", caution: "An incomplete handshake alone is not a flood." },
  { id: "distributed_syn", title: "Distributed-source SYN flood", family: "DDoS", description: "A SYN surge arriving from many apparent source addresses.", signal: "Source-IP diversity/entropy · SYN rate · target concentration", caution: "Passive telemetry cannot prove that source addresses were spoofed." },
  { id: "udp_reflection", title: "UDP reflection / amplification", family: "DDoS", description: "High-rate UDP traffic with reflection or amplification indicators.", signal: "UDP rate · source diversity · byte/port pattern", caution: "A UDP surge does not prove a reflector was used." },
  { id: "recon", title: "Reconnaissance / port scan", family: "Recon", description: "One source fans out across destination ports or hosts.", signal: "Unique ports · unique hosts · connection outcome", caution: "Authorized scanners should be checked against policy context." },
  { id: "c2", title: "C2 beaconing", family: "C2", description: "Repeated communication with suspiciously regular timing.", signal: "Inter-arrival interval · jitter · destination set", caution: "Health checks can also be periodic; context matters." },
  { id: "dga", title: "DGA-like DNS", family: "DNS", description: "Domain names whose lexical pattern resembles generated names.", signal: "Domain entropy · n-grams · model probability", caution: "A generated-looking name is not proof of malware." },
  { id: "dns_tunnel", title: "DNS tunnelling", family: "DNS", description: "Long or encoded-looking repeated DNS queries and record anomalies.", signal: "Query length · entropy · TXT ratio · repetition", caution: "Some legitimate services use long DNS names." },
  { id: "encrypted", title: "Encrypted-session anomaly", family: "TLS / QUIC", description: "Unusual TLS/QUIC metadata without decrypting traffic.", signal: "JA3/JA4 prevalence · packet sizes · timing", caution: "An anomaly is not definitive malware identification." },
  { id: "exfil", title: "Data exfiltration", family: "Exfil", description: "Unusual outbound volume relative to inbound traffic.", signal: "Outbound bytes · inbound bytes · ratio · policy", caution: "Approved backups can look similar; review destination and purpose." },
] as const;

export type AttackId = typeof ATTACKS[number]["id"] | "other";

export function attackId(alert: Pick<AnalystAlert, "subtype" | "threat_type">): AttackId {
  const subtype = alert.subtype;
  if (subtype === "distributed_source_syn_flood" || subtype === "suspected_spoofed_source_flood") return "distributed_syn";
  if (subtype === "syn_flood") return "syn_flood";
  if (subtype === "udp_reflection_amplification" || subtype === "udp_flood") return "udp_reflection";
  if (["vertical_port_scan", "horizontal_host_scan", "multi_host_port_scan"].includes(subtype) || alert.threat_type === "reconnaissance") return "recon";
  if (subtype === "periodic_beacon" || alert.threat_type === "command_and_control") return "c2";
  if (subtype === "dga_like_domain") return "dga";
  if (subtype === "dns_tunnelling") return "dns_tunnel";
  if (subtype === "encrypted_session_metadata_anomaly" || alert.threat_type === "encrypted_session_threat") return "encrypted";
  if (subtype === "outbound_volume_anomaly" || alert.threat_type === "data_exfiltration") return "exfil";
  return "other";
}

export function buildAttackAnalytics(alerts: AnalystAlert[], incidents: AnalystIncident[], bucketCount = 12,
                                     captureWindow?: { start: number | null | undefined; end: number | null | undefined }) {
  const member = new Map<string, AnalystIncident>();
  for (const incident of incidents) for (const id of incident.alert_ids) member.set(id, incident);
  const groups = new Map<AttackId, AnalystAlert[]>();
  for (const alert of alerts) {
    const id = attackId(alert);
    groups.set(id, [...(groups.get(id) ?? []), alert]);
  }
  const observedTimes = alerts.map((alert) => alert.window_start).filter(Number.isFinite);
  const observedStart = observedTimes.reduce((value, current) => Math.min(value, current), Infinity);
  const observedEnd = observedTimes.reduce((value, current) => Math.max(value, current), -Infinity);
  const start = typeof captureWindow?.start === "number" && Number.isFinite(captureWindow.start) ? captureWindow.start : observedStart;
  const end = typeof captureWindow?.end === "number" && Number.isFinite(captureWindow.end) ? captureWindow.end : observedEnd;
  const bucketsFor = (items: AnalystAlert[]) => {
    const buckets = Array<number>(bucketCount).fill(0);
    for (const item of items) {
      if (!Number.isFinite(item.window_start)) continue;
      const index = end === start ? 0 : Math.min(bucketCount - 1, Math.floor((item.window_start - start) / (end - start) * bucketCount));
      buckets[Math.max(0, index)] += 1;
    }
    return buckets;
  };
  const rows = [...ATTACKS, { id: "other" as const, title: "Other detections", family: "Other", description: "Alert subtype not mapped to a named attack view.", signal: "See detector evidence", caution: "Review the raw subtype before interpretation." }]
    .map((attack) => {
      const items = groups.get(attack.id) ?? [];
      const related = new Set(items.map((alert) => member.get(alert.alert_id)?.incident_id).filter(Boolean));
      return { ...attack, alerts: items, count: items.length, incidents: related.size,
        averageConfidence: items.length ? Math.round(items.reduce((sum, item) => sum + item.confidence, 0) / items.length * 100) : null,
        highestRisk: items.length ? Math.max(0, ...items.map((item) => member.get(item.alert_id)?.risk_score ?? 0)) : null,
        buckets: bucketsFor(items),
      };
    }).filter((row) => row.id !== "other" || row.count > 0);
  return { rows, start: Number.isFinite(start) ? start : 0, end: Number.isFinite(end) ? end : 0, totalAlerts: alerts.length, detectedBehaviours: rows.filter((row) => row.id !== "other" && row.count > 0).length,
    incidentCount: new Set(incidents.map((incident) => incident.incident_id)).size };
}
