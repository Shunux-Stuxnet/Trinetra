from typing import Annotated, List, Optional, TypedDict

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import interrupt

from .config import CHROMA_DIR, DATA_DIR
from .llm import ioc_extractor_chain, mitre_rewriter_chain, playbook_grader_chain, report_generator_chain
from .models import build_risk_scorecard, discover_iocs
from .osint import block_ioc_on_firewall, enrich_indicator


def build_secops_retriever():
    docs = [
        Document("PLAYBOOK ID: PB-101 | MITRE ATT&CK: T1071 Application Layer Protocol (C2 Beaconing). Indicators: Outbound connections to high-abuse IPs, Tor exit nodes, or Cobalt Strike servers on port 443/8443. Remediation: Immediately isolate the source endpoint, block the remote C2 IP, dump volatile memory, and file a CERT-In incident report within 6 hours.", metadata={"playbook_id": "PB-101", "mitre_id": "T1071"}),
        Document("PLAYBOOK ID: PB-102 | MITRE ATT&CK: T1059.001 PowerShell. Indicators: powershell.exe with -enc, -EncodedCommand, Base64 payloads, or hidden windows from temp directories or Office macros. Remediation: Terminate the process tree, revoke Kerberos tickets, capture AMSI logs, and scan scheduled task persistence.", metadata={"playbook_id": "PB-102", "mitre_id": "T1059.001"}),
        Document("PLAYBOOK ID: PB-103 | MITRE ATT&CK: T1566 Phishing and Typosquatting. Indicators: Newly registered domains mimicking corporate login portals. Verified infrastructure domains older than 365 days with clean reputation are Low Severity false positives.", metadata={"playbook_id": "PB-103", "mitre_id": "T1566"}),
    ]
    print("[Pre-Flight 2/2] ChromaDB: Loading local CPU embeddings...")
    vectorstore = Chroma(collection_name="trinetra_secops_playbooks", embedding_function=HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2"), persist_directory=str(CHROMA_DIR))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not vectorstore.get().get("ids"):
        vectorstore.add_documents(docs)
        print(f"[Pre-Flight 2/2] ChromaDB: Created persistent index at {CHROMA_DIR}")
    else:
        print(f"[Pre-Flight 2/2] ChromaDB: Reusing persistent index at {CHROMA_DIR}")
    return vectorstore.as_retriever(search_kwargs={"k": 1})


retriever = build_secops_retriever()


class ThreatState(TypedDict):
    messages: Annotated[list, add_messages]
    raw_alert: str
    extracted_ioc: str
    ioc_type: str
    discovered_iocs: List[dict[str, str]]
    search_query: str
    osint_data: dict
    risk_score: int
    scorecard: dict
    playbook_text: str
    playbook_relevant: str
    rewrite_count: int
    containment_approved: Optional[bool]
    containment_status: str
    final_report: Optional[dict]


def extract_ioc_node(state: ThreatState):
    parsed = ioc_extractor_chain.invoke({"raw_alert": state["raw_alert"]})
    return {"extracted_ioc": parsed.extracted_ioc, "ioc_type": parsed.ioc_type, "discovered_iocs": discover_iocs(state["raw_alert"], parsed.extracted_ioc), "search_query": parsed.search_query, "rewrite_count": 0, "containment_status": "No active firewall block required."}


def osint_enrichment_node(state: ThreatState):
    indicators = [enrich_indicator(item) for item in state["discovered_iocs"] or [{"ioc": state["extracted_ioc"], "type": state["ioc_type"]}]]
    risk = max((item.get("abuse_confidence_score", 50) for item in indicators), default=50)
    return {"osint_data": {"source": "Trinetra_Multi_Source_Investigation", "ioc": state["extracted_ioc"], "abuse_confidence_score": risk, "threat_tags": sorted({tag for item in indicators for tag in item.get("threat_tags", [])}), "indicators": indicators}, "risk_score": risk}


def retrieve_playbook_node(state: ThreatState):
    docs = retriever.invoke(state["search_query"])
    return {"playbook_text": docs[0].page_content if docs else "No matching playbook found."}


def grade_playbook_node(state: ThreatState):
    grade = playbook_grader_chain.invoke({"raw_alert": state["raw_alert"], "osint_data": state["osint_data"], "playbook_text": state["playbook_text"]})
    scorecard = build_risk_scorecard(state["osint_data"], state["raw_alert"], state["discovered_iocs"], state["playbook_text"])
    return {"playbook_relevant": grade.relevant, "scorecard": scorecard, "risk_score": scorecard["overall_score"]}


def rewrite_mitre_query_node(state: ThreatState):
    rewritten = mitre_rewriter_chain.invoke({"raw_alert": state["raw_alert"], "current_query": state["search_query"]})
    return {"search_query": rewritten.mitre_query, "rewrite_count": state["rewrite_count"] + 1}


def human_firewall_gate_node(state: ThreatState):
    approval = interrupt({"alert_notice": "CRITICAL THREAT DETECTED - HUMAN SOC APPROVAL REQUIRED", "proposed_tool": "block_ioc_on_firewall", "target_ioc": state["extracted_ioc"], "risk_score": state["risk_score"], "osint_tags": state["osint_data"].get("threat_tags", []), "question": "Approve perimeter firewall block? Pass True to approve or False to reject."})
    if approval is True:
        result = block_ioc_on_firewall.invoke({"ioc": state["extracted_ioc"], "reason": f"Trinetra SOC Auto-Triage (Risk Score {state['risk_score']}/100)"})
        return {"containment_approved": True, "containment_status": result}
    return {"containment_approved": False, "containment_status": f"SOC Analyst REJECTED automated firewall block for {state['extracted_ioc']}. Escalated to manual review."}


def generate_report_node(state: ThreatState):
    report = report_generator_chain.invoke({"raw_alert": state["raw_alert"], "extracted_ioc": state["extracted_ioc"], "ioc_type": state["ioc_type"], "osint_data": state["osint_data"], "risk_score": state["risk_score"], "containment_status": state["containment_status"], "playbook_text": state["playbook_text"]})
    scorecard = build_risk_scorecard(state["osint_data"], state["raw_alert"], state["discovered_iocs"], state["playbook_text"])
    final_report = report.model_dump()
    final_report.update({"severity": scorecard["severity"], "scorecard": scorecard, "indicators": state["discovered_iocs"], "containment_status": state["containment_status"]})
    return {"final_report": final_report, "scorecard": scorecard, "risk_score": scorecard["overall_score"]}


def build_trinetra_graph():
    builder = StateGraph(ThreatState)
    for name, node in {"extract_ioc": extract_ioc_node, "osint_enrichment": osint_enrichment_node, "retrieve_playbook": retrieve_playbook_node, "grade_playbook": grade_playbook_node, "rewrite_mitre_query": rewrite_mitre_query_node, "human_firewall_gate": human_firewall_gate_node, "generate_report": generate_report_node}.items():
        builder.add_node(name, node)
    builder.add_edge(START, "extract_ioc")
    builder.add_edge("extract_ioc", "osint_enrichment")
    builder.add_edge("osint_enrichment", "retrieve_playbook")
    builder.add_edge("retrieve_playbook", "grade_playbook")
    builder.add_conditional_edges("grade_playbook", lambda state: "rewrite_mitre_query" if state["playbook_relevant"] == "no" and state["rewrite_count"] < 2 else ("human_firewall_gate" if state["risk_score"] >= 80 else "generate_report"), {"rewrite_mitre_query": "rewrite_mitre_query", "human_firewall_gate": "human_firewall_gate", "generate_report": "generate_report"})
    builder.add_edge("rewrite_mitre_query", "retrieve_playbook")
    builder.add_edge("human_firewall_gate", "generate_report")
    builder.add_edge("generate_report", END)
    return builder.compile(checkpointer=InMemorySaver())
