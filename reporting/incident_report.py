"""Incident report generation (JSON + PDF)."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

import config
from database import repository as repo


def build_report(alert_id: str) -> dict:
    a = repo.get_alert(alert_id)
    if a is None:
        raise KeyError(alert_id)
    inv = repo.get_investigations(alert_id)
    llm = json.loads(inv.iloc[0]["response_json"]) if not inv.empty else None
    ev = repo.get_event(a["event_id"]) or {}
    audit = repo.get_audit(alert_id)
    timeline = [{"time": a["created_at"], "event": "First related event observed"}, {"time": a["detected_at"], "event": f"Detected by {a['detection_method']}"}]
    if a.get("acknowledged_at"):
        timeline.append({"time": a["acknowledged_at"], "event": "Acknowledged by analyst"})
    if a.get("responded_at"):
        timeline.append({"time": a["responded_at"], "event": "Response action recorded"})
    timeline += [{"time": r["ts"], "event": f"{r['actor']}: {r['action']} {r['detail'][:80]}"} for r in audit.to_dict("records")]
    return {
        "incident_id": a["alert_id"], "title": a["title"], "generated_at": repo.now_iso(),
        "synthetic_data_notice": "Demonstration data is SYNTHETIC unless a real dataset/SIEM feed was configured.",
        "incident_summary": (llm or {}).get("incident_summary") or f"{a['attack_category']} detected on {a['hostname']} ({a['event_count']} related events).",
        "event_timeline": timeline, "detection_method": a["detection_method"], "detection_rules": a["rule_names"],
        "ml_prediction": a["ml_prediction"], "prediction_confidence": a["ml_confidence"], "anomaly_score": a["anomaly_score"],
        "risk_score": a["risk_score"], "risk_level": a["risk_level"], "risk_overridden": bool(a["risk_overridden"]),
        "risk_components": json.loads(a["risk_components_json"] or "{}"), "mitre_mapping": json.loads(a["mitre_json"] or "[]"),
        "supporting_evidence": (llm or {}).get("evidence", []) + repo.get_evidence(alert_id)["evidence_text"].tolist(),
        "llm_investigation": llm, "recommended_response": (llm or {}).get("recommended_actions", []),
        "analyst_notes": repo.get_notes(alert_id).to_dict("records"), "final_status": a["status"],
        "raw_event": {k: ev.get(k) for k in ("event_id", "timestamp", "source", "description", "src_ip", "dst_ip", "hostname", "username")},
        "audit_trail": audit.to_dict("records")}


def to_json(report: dict, path: Path | None = None) -> Path:
    path = path or config.REPORTS_DIR / f"{report['incident_id']}.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def to_pdf(report: dict, path: Path | None = None) -> Path:
    path = path or config.REPORTS_DIR / f"{report['incident_id']}.pdf"
    ss = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    P = lambda t, s="BodyText": Paragraph(str(t).replace("&", "&amp;").replace("<", "&lt;"), ss[s])
    el = [P(f"Incident Report {report['incident_id']}", "Title"), P(report["title"], "Heading3"), P(report["synthetic_data_notice"], "Italic"), Spacer(1, 8)]
    el += [P("Summary", "Heading2"), P(report["incident_summary"])]
    kv = [["Detection method", report["detection_method"]], ["Rules", report["detection_rules"]], ["ML prediction", report["ml_prediction"]],
          ["ML probability", report["prediction_confidence"]], ["Anomaly score (not a probability)", report["anomaly_score"]],
          ["Risk score", f"{report['risk_score']} ({report['risk_level']})" + (" - analyst override" if report["risk_overridden"] else "")],
          ["Final status", report["final_status"]]]
    t = Table([[P(a), P(b)] for a, b in kv], colWidths=[5 * cm, 11 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .3, colors.grey), ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke)]))
    el += [Spacer(1, 6), t, P("MITRE ATT&CK mapping", "Heading2")]
    el += [P(f"{m['id']} {m['name']} [{m['tactic']}] - {m['status']}") for m in report["mitre_mapping"]] or [P("none")]
    el += [P("Supporting evidence", "Heading2")] + [P(f"- {e}") for e in report["supporting_evidence"]]
    llm = report["llm_investigation"]
    if llm:
        el += [P("LLM investigation (human review required)", "Heading2"), P("Confirmed facts: " + "; ".join(llm.get("confirmed_facts", []))),
               P("Hypotheses: " + "; ".join(llm.get("hypotheses", []))), P("Investigation steps", "Heading3")] + [P(f"{i+1}. {s}") for i, s in enumerate(llm.get("investigation_steps", []))]
        el += [P("Limitations: " + "; ".join(llm.get("limitations", [])))]
    el += [P("Recommended response (not executed; needs approval)", "Heading2")] + [P(f"- {r}") for r in report["recommended_response"]]
    el += [P("Event timeline", "Heading2")] + [P(f"{x['time']} - {x['event']}") for x in report["event_timeline"]]
    el += [P("Analyst notes", "Heading2")] + [P(f"{n['ts']} {n['author']}: {n['note']}") for n in report["analyst_notes"]] or [P("none")]
    doc.build(el)
    return path
