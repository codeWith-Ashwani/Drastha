import { useEffect, useRef, useState } from "react";
import { Download } from "lucide-react";

export function SiemExport({ runId }: { runId: string }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  const download = async () => {
    if (request.current) return;
    const controller = new AbortController();
    request.current = controller;
    setPending(true); setError("");
    try {
      const response = await fetch(`/api/analysis-runs/${encodeURIComponent(runId)}/export?format=ndjson`,
        { signal: controller.signal, credentials: "same-origin" });
      if (!response.ok) {
        const failure = await response.json().catch(() => ({}));
        throw new Error(typeof failure.detail === "string" ? failure.detail : "SIEM export could not be downloaded.");
      }
      const blob = await response.blob();
      if (controller.signal.aborted) return;
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "drastha-siem-export.ndjson";
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "SIEM export failed.");
    } finally {
      if (!controller.signal.aborted) setPending(false);
      request.current = null;
    }
  };
  return <div className="siem-export">
    <button className="secondary" disabled={pending} onClick={() => void download()}>
      <Download size={14} />{pending ? "Preparing SIEM export…" : "Download SIEM NDJSON"}
    </button>
    {error && <p className="scope-note" role="alert">{error}</p>}
  </div>;
}
