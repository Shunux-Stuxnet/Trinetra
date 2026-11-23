import re
from typing import Any, List, Literal

from pydantic import BaseModel, Field


class IOCExtractionSchema(BaseModel):
    extracted_ioc: str = Field(description="Primary IP, domain, or behavior. Use 'none' if absent.")
    ioc_type: Literal["ip", "domain", "behavior"] = Field(description="Indicator type.")
    search_query: str = Field(description="Initial SOC playbook search query.")


class PlaybookGradeSchema(BaseModel):
    relevant: Literal["yes", "no"]
    reasoning: str


class MITRERewriteSchema(BaseModel):
    mitre_query: str


class IncidentReportSchema(BaseModel):
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    mitre_mapping: str
    executive_summary: str
    remediation_steps: List[str]


class RiskScorecard(BaseModel):
    overall_score: int = Field(ge=0, le=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: int = Field(ge=0, le=100)
    dimensions: dict[str, int]
    rationale: List[str]
    recommended_actions: List[str]


def discover_iocs(alert: str, primary_ioc: str = "") -> List[dict[str, str]]:
    candidates: list[tuple[str, str]] = []
    candidates.extend(("ip", value) for value in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", alert))
    candidates.extend(("cve", value.upper()) for value in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", alert, re.I))
    candidates.extend(
        ("domain", value.lower())
        for value in re.findall(r"(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", alert, re.I)
    )
    if primary_ioc and primary_ioc.lower() != "none":
        value = primary_ioc.strip().lower()
        kind = "ip" if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value) else (
            "cve" if re.fullmatch(r"cve-\d{4}-\d{4,7}", value) else ("domain" if "." in value else "behavior")
        )
        candidates.insert(0, (kind, value))
    seen: set[tuple[str, str]] = set()
    result = []
    for kind, value in candidates:
        if (kind, value) not in seen:
            seen.add((kind, value))
            result.append({"ioc": value, "type": kind})
    return result[:12]


def build_risk_scorecard(osint_data: dict[str, Any], alert: str, iocs: List[dict[str, str]], playbook_text: str) -> dict[str, Any]:
    reputation = max([int(item.get("abuse_confidence_score", 0)) for item in osint_data.get("indicators", [])] or [int(osint_data.get("abuse_confidence_score", 0))])
    behavior = 85 if re.search(r"\b(-enc|encodedcommand|powershell|beacon|cobalt strike|credential harvesting|ransomware)\b", alert, re.I) else 35
    exposure = min(100, 25 + 15 * len(iocs))
    recency = max([max(0, 100 - int(item.get("domain_age_days", 365)) // 3) for item in osint_data.get("indicators", []) if "domain_age_days" in item] or [30])
    context = 80 if playbook_text and "No matching" not in playbook_text else 30
    score = max(0, min(100, round(reputation * .45 + behavior * .25 + exposure * .10 + recency * .10 + context * .10)))
    severity = "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW"
    confidence = min(98, 45 + min(35, len(iocs) * 10) + (15 if osint_data.get("source") else 0))
    rationale = []
    if reputation >= 80:
        rationale.append(f"Threat-intelligence reputation is high ({reputation}/100).")
    if behavior >= 80:
        rationale.append("Alert behavior matches a known malicious execution or command-and-control pattern.")
    if recency >= 70:
        rationale.append("At least one indicator has strong recency risk.")
    if context >= 70:
        rationale.append("A relevant SOC playbook was retrieved for this investigation.")
    if not rationale:
        rationale.append("No high-confidence malicious signal was found; continue monitoring and validate the source.")
    actions = ["Isolate the affected endpoint.", "Preserve volatile evidence and relevant logs.", "Block confirmed malicious indicators."] if score >= 65 else ["Validate the alert with the asset owner.", "Monitor the indicator and close only with documented evidence."]
    return RiskScorecard(overall_score=score, severity=severity, confidence=confidence, dimensions={"reputation": reputation, "behavior": behavior, "exposure": exposure, "recency": recency, "context": context}, rationale=rationale, recommended_actions=actions).model_dump()
