"""Score frozen CTU DGA strings and exercise the real upload-analysis path."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
from aegisflow.api_store import IncidentRepository
from aegisflow.dns_calibration import gate_failures, scored_metrics
from aegisflow.dns_model import DNSHashedLogisticModel, DNSLabelledDomain, DNSNgramModel
from aegisflow.upload_analysis import analyse_uploaded_replay
from freeze_sih_ctu_dga_holdout import FIXTURE, LABELS, verify


def load_research_model(path: Path) -> DNSNgramModel:
    payload = json.loads(path.read_text(encoding="utf-8"))
    model_type = payload.get("model_type")
    if model_type == "hashed_character_logistic_regression":
        return DNSHashedLogisticModel(payload)
    if model_type == "character_ngram_multinomial_naive_bayes":
        return DNSNgramModel(payload)
    raise ValueError(f"Unsupported research model type: {model_type}")


def upload_metrics(model: DNSNgramModel, rows: list[DNSLabelledDomain]) -> dict:
    records = []
    for index, row in enumerate(rows):
        third, fourth = divmod(index, 250)
        records.append({
            "ts": 1800000000 + index * 0.01,
            "uid": f"CTU-{row.label}-{index:05d}",
            "id.orig_h": f"10.{100 + row.label}.{third}.{fourth + 1}",
            "id.orig_p": 40000 + index % 20000,
            "id.resp_h": "10.200.0.53", "id.resp_p": 53,
            "proto": "udp", "query": row.domain, "qtype_name": "A",
            "rcode_name": "UNKNOWN", "trans_id": index + 1,
        })
    content = "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records)
    with tempfile.TemporaryDirectory(prefix="drastha-ctu-dga-") as temporary:
        repository = IncidentRepository(Path(temporary) / "incidents.db")
        session = AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        session = AnalysisSession(session.profile, context_policy=session.context_policy,
                                  dns_model=model)
        result = analyse_uploaded_replay("ctu-dga-holdout.jsonl", content, repository,
                                         session=session)
    detected = {flow_id for alert in result["alerts"]
                if alert["subtype"] == "dga_like_domain"
                for flow_id in alert.get("flow_ids", [])}
    expected = {record["uid"] for record in records}
    positives = sum(row.label for row in rows)
    tp = sum(record["uid"] in detected and row.label == 1
             for record, row in zip(records, rows))
    fp = sum(record["uid"] in detected and row.label == 0
             for record, row in zip(records, rows))
    metrics = {"tp": tp, "fp": fp, "fn": positives - tp,
               "tn": len(rows) - positives - fp,
               "records": len(rows), "detected_uids": len(detected & expected),
               "quality": result["quality"]["status"],
               "accepted": result["quality"]["records_accepted"],
               "rejected": result["quality"]["records_rejected"]}
    metrics["recall"] = tp / positives
    metrics["fpr"] = fp / (len(rows) - positives)
    return metrics


def assess(model: DNSNgramModel, rows: list[DNSLabelledDomain], gates: dict) -> dict:
    probabilities = [model.predict_probability(row.domain) for row in rows]
    threshold = float(model.payload.get("operating_threshold", 0.5))
    direct = scored_metrics(rows, probabilities, threshold)
    calibration_gates = dict(gates)
    calibration_gates.setdefault("minimum_family_recall", gates["minimum_recall"])
    failures = gate_failures(direct, calibration_gates)
    actual_upload = upload_metrics(model, rows)
    if (direct["tp"], direct["fp"], direct["fn"], direct["tn"]) != tuple(
            actual_upload[key] for key in ("tp", "fp", "fn", "tn")):
        failures.append("upload analysis predictions differ from direct model scoring")
    if (actual_upload["quality"] != "healthy" or actual_upload["accepted"] != len(rows)
            or actual_upload["rejected"] != 0):
        failures.append("upload analysis did not accept the frozen holdout with healthy quality")
    return {"model_type": model.payload.get("model_type"), "threshold": threshold,
            "direct_metrics": direct, "upload_metrics": actual_upload,
            "gate_failures": failures, "passed": not failures}


def audit(candidate_path: Path | None) -> dict:
    freeze = verify()
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    rows = [DNSLabelledDomain(item["domain"], int(item["label"]),
                              item["source_class"], "external")
            for item in map(json.loads, FIXTURE.read_text(encoding="utf-8").splitlines())]
    deployed = DNSNgramModel.load(ROOT / "output/models/dns_dga_demo.json")
    models = {"deployed_demo": assess(deployed, rows, labels["gates"])}
    if candidate_path is not None:
        models["research_candidate"] = assess(load_research_model(candidate_path), rows,
                                               labels["gates"])
    return {
        "schema_version": "drastha-sih-ctu-dga-holdout-audit-v1",
        "provenance_valid": True, "prediction_blind_freeze": True,
        "source_sha256": freeze["source_sha256"],
        "fixture_sha256": freeze["fixture_sha256"], "records": len(rows),
        "gates": labels["gates"], "models": models,
        "promotion_eligible": bool(models.get("research_candidate", {}).get("passed")),
        "limitations": [labels["claim_boundary"],
                        "Passing this holdout alone does not establish operational DGA accuracy.",
                        "The research model remains non-deployable unless the existing cryptographic promotion workflow approves it."],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_ctu_dga_holdout_audit.json")
    args = parser.parse_args()
    candidate = args.candidate
    if candidate is not None and not candidate.is_absolute():
        candidate = ROOT / candidate
    report = audit(candidate)
    destination = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")
    print(json.dumps({name: {"passed": item["passed"],
                             "tp": item["direct_metrics"]["tp"],
                             "fp": item["direct_metrics"]["fp"],
                             "fn": item["direct_metrics"]["fn"],
                             "tn": item["direct_metrics"]["tn"]}
                      for name, item in report["models"].items()}, sort_keys=True))
    return 0 if report["promotion_eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
