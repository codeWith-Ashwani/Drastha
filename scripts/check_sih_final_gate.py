"""Re-run the finite SIH acceptance gate without promoting failed evidence."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sih_gate2_flow import audit as flow_audit
from check_sih_gate2_metadata import audit as metadata_audit
from check_sih_gate2_dga import audit as dga_audit
from check_sih_gate2_tls import audit as tls_audit
from check_sprint33_release import audit as release_audit


def assess(release: dict, flow: dict, metadata: dict, dga: dict, tls: dict,
           suites: dict) -> dict:
    """Keep functional completion distinct from independent detection proof."""
    dga_totals = dga["totals"]
    tls_measurement = tls["quality_healthy"] and tls["measured_only"]
    gates = {
        "prior_replay_stream_safety_schema_throughput": bool(release["passed"]),
        "fresh_flow_scenarios": bool(flow["passed"]),
        "fresh_slow_c2_iodine_scenarios": bool(metadata["passed"]),
        "published_dga_quality": bool(dga["quality_healthy"]),
        "tls_metadata_measured_without_decryption": bool(tls_measurement),
        "python_tests": bool(suites["python"]["passed"]),
        "frontend_tests": bool(suites["frontend"]["passed"]),
        "dashboard_build": bool(suites["build"]["passed"]),
        # These intentionally require at least one measured positive; passing
        # the old synthetic replay cannot substitute for fresh-source proof.
        "fresh_published_dga_detection": dga_totals["tp"] > 0 and dga_totals["fp"] == 0,
        "fresh_measured_tls_positive": tls_measurement and tls["tp_sessions"] > 0
                                       and tls["fp_sessions"] == 0,
    }
    functional = all(gates[key] for key in (
        "prior_replay_stream_safety_schema_throughput", "fresh_flow_scenarios",
        "fresh_slow_c2_iodine_scenarios", "published_dga_quality",
        "tls_metadata_measured_without_decryption", "python_tests",
        "frontend_tests", "dashboard_build"))
    evidence = functional and gates["fresh_published_dga_detection"] and gates["fresh_measured_tls_positive"]
    return {
        "schema_version": "drastha-sih-final-gate-v1",
        "functional_prototype_verified": functional,
        "fresh_source_evidence_complete": evidence,
        "sih_level": "evidence_complete" if evidence else "functional_prototype_with_validation_gaps",
        "production_ready": False,
        "release_promotion_allowed": evidence,
        "gates": gates,
        "results": {
            "prior_release": {"release_id": release["release_id"], "passed": release["passed"],
                              "throughput": release["verified_results"]["performance"]},
            "fresh_flow": flow["totals"],
            "fresh_slow_c2_iodine": metadata["totals"],
            "published_dga": dga_totals,
            "tls_changed_handshake_control": {
                "tp": tls["tp_sessions"], "fp": tls["fp_sessions"],
                "fn": tls["fn_sessions"], "tn": tls["tn_sessions"],
                "coverage": tls["feature_coverage"]["counts"],
            },
            "suites": suites,
        },
        "ps_evidence_map": [
            {"requirement": "read-only passive input and no return action", "status": "verified_lab",
             "proof": "scripts/check_sprint33_release.py; scripts/generate_sih_gate2_flow_capture.sh"},
            {"requirement": "PCAP and flow-derived incremental ingest", "status": "verified_lab",
             "proof": "scripts/check_sprint33_release.py; docs/SPRINT_36.md"},
            {"requirement": "SYN and UDP volumetric/protocol DDoS", "status": "verified_lab",
             "proof": "output/sih_gate2_flow_audit.json"},
            {"requirement": "spoofed-source hypothesis", "status": "limited",
             "proof": "docs/SPRINT_36.md; passive source diversity cannot prove spoofing"},
            {"requirement": "C2 periodicity and inter-arrival", "status": "verified_lab",
             "proof": "output/sih_gate2_metadata_audit.json"},
            {"requirement": "DGA from published algorithm samples", "status": "failed_fresh_validation",
             "proof": "output/sih_gate2_dga_audit.json"},
            {"requirement": "DNS tunnelling query/type anomalies", "status": "verified_lab",
             "proof": "output/sih_gate2_metadata_audit.json"},
            {"requirement": "TLS metadata without payload decryption", "status": "measured_positive_missing",
             "proof": "output/sih_gate2_tls_audit.json"},
            {"requirement": "reconnaissance fan-out", "status": "verified_lab",
             "proof": "output/sih_gate2_flow_audit.json"},
            {"requirement": "exfiltration volume asymmetry", "status": "behaviour_only",
             "proof": "output/sih_gate2_flow_audit.json; volume is not theft proof"},
            {"requirement": "labelled alerts, confidence, evidence and dashboard", "status": "verified_demo",
             "proof": "scripts/check_sprint33_release.py; web/tests/replay-evidence.test.mjs"},
            {"requirement": "bounded latency and stated throughput", "status": "verified_lab",
             "proof": "output/sprint33_release_audit.json (50 records/s, 60 seconds)"},
        ],
        "limitations": [
            "Old 452/153-record controlled scores are integration regressions, not independent accuracy.",
            "The published DGA sample exposes a deployed-model generalization failure.",
            "The changed TLS lab control is not malware and did not independently deviate in size/timing; a measured positive is still missing.",
            "Raw binary captures are local/gitignored; a clean clone can verify committed fixture hashes but must regenerate captures for raw checks.",
            "A private namespace is a lab simulation, not a physical data diode or production mirror.",
        ],
    }


def _run(name: str, command: list[str], cwd: Path, count_pattern: str | None = None) -> dict:
    executable = (shutil.which(command[0] + ".cmd") or shutil.which(command[0])
                  if os.name == "nt" else shutil.which(command[0]))
    if not executable:
        return {"passed": False, "exit_code": None, "count": None,
                "command": command, "output_tail": f"Executable not found: {command[0]}"}
    result = subprocess.run([executable, *command[1:]], cwd=cwd,
                            capture_output=True, text=True, check=False)
    combined = result.stdout + result.stderr
    match = re.search(count_pattern, combined) if count_pattern else None
    return {"passed": result.returncode == 0, "exit_code": result.returncode,
            "count": int(match.group(1)) if match else None,
            "command": command, "output_tail": combined[-1600:] if result.returncode else combined[-350:]}


def audit(run_suites: bool = True) -> dict:
    if run_suites:
        suites = {
            "python": _run("python", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                           ROOT, r"Ran (\d+) tests? in"),
            "frontend": _run("frontend", ["node", "--test", "tests/*.test.mjs"],
                             ROOT / "web", r"# tests (\d+)"),
            "build": _run("build", ["npm", "run", "build"], ROOT / "web"),
        }
    else:
        suites = {name: {"passed": False, "not_run": True} for name in ("python", "frontend", "build")}
    return assess(release_audit(), flow_audit(), metadata_audit(), dga_audit(), tls_audit(), suites)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_final_gate_audit.json")
    parser.add_argument("--skip-suites", action="store_true", help="diagnostic only; cannot pass the gate")
    args = parser.parse_args()
    report = audit(run_suites=not args.skip_suites)
    path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"functional_prototype_verified": report["functional_prototype_verified"],
                      "fresh_source_evidence_complete": report["fresh_source_evidence_complete"],
                      "sih_level": report["sih_level"], "report": str(path)}, sort_keys=True))
    return 0 if report["release_promotion_allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
