import uuid

from langgraph.types import Command

from .graph import build_trinetra_graph


def print_final_report(report: dict) -> None:
    print("\n" + "=" * 72)
    print(f"TRINETRA SOC INCIDENT REPORT | SEVERITY: {report['severity']}")
    print("=" * 72)
    scorecard = report.get("scorecard", {})
    print(f"RISK SCORE   : {scorecard.get('overall_score', 'n/a')}/100 | Confidence: {scorecard.get('confidence', 'n/a')}%")
    print(f"MITRE ATT&CK : {report['mitre_mapping']}")
    if report.get("indicators"):
        print("INDICATORS   : " + ", ".join(item["ioc"] for item in report["indicators"]))
    print(f"Summary      : {report['executive_summary']}")
    if scorecard.get("dimensions"):
        print("SCORECARD    : " + " | ".join(f"{key}={value}" for key, value in scorecard["dimensions"].items()))
    print("Remediation  :")
    for index, step in enumerate(report["remediation_steps"], 1):
        print(f"  {index}. {step}")
    print("=" * 72 + "\n")


def run_demo() -> None:
    app = build_trinetra_graph()
    scenarios = [
        ("CRITICAL C2 BEACON -> OSINT -> HITL FIREWALL INTERRUPT", "SIEM Alert: Workstation FIN-LAPTOP-09 initiated repeated encrypted beacons to 185.220.101.45 on port 443.", True),
        ("OBFUSCATED POWERSHELL ALERT -> MITRE PLAYBOOK TRIAGE", "EDR Alert: User temp directory spawned weird hidden script with -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=", False),
        ("BENIGN CDN TRAFFIC -> OSINT ALLOWLIST -> AUTO-CLOSE", "Proxy Alert: High volume HTTPS requests from Marketing subnet to cdn.cloudflare.net.", False),
    ]
    for title, alert, requires_approval in scenarios:
        print("\n" + "#" * 72)
        print(f"SCENARIO: {title}")
        print("#" * 72)
        config = {"configurable": {"thread_id": f"soc-incident-{uuid.uuid4().hex[:6]}"}}
        result = app.invoke({"raw_alert": alert}, config=config)
        if requires_approval and "__interrupt__" in result:
            print(f"\n[PAUSED] Analyst approval payload: {result['__interrupt__'][0].value}")
            approved = input("\n[SOC Analyst Action] Approve firewall block? (y/n, default=y): ").strip().lower() in ("", "y", "yes")
            result = app.invoke(Command(resume=approved), config=config)
        print_final_report(result["final_report"])
