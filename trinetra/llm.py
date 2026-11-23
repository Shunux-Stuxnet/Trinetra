import os
from typing import Type

from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from .models import IOCExtractionSchema, IncidentReportSchema, MITRERewriteSchema, PlaybookGradeSchema


def build_structured_llm_with_fallbacks(schema: Type[BaseModel]):
    candidates = []
    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if groq_key and not groq_key.startswith("gsk_your_"):
        for model in os.getenv("GROQ_MODELS", "llama-3.3-70b-versatile,llama-3.1-8b-instant").split(","):
            candidates.append(ChatGroq(model=model.strip(), temperature=0, max_retries=0).with_structured_output(schema))
    if openrouter_key and not openrouter_key.startswith("sk-or-v1-your_"):
        models = [m.strip() for m in os.getenv("OPENROUTER_FREE_MODELS", "nvidia/nemotron-3.5-lightning:free,google/gemma-4-31b-it:free,openrouter/free").split(",") if m.strip()]
        for index, model in enumerate(models):
            fallback_models = models[index + 1:index + 3]
            candidates.append(ChatOpenAI(base_url="https://openrouter.ai/api/v1", api_key=openrouter_key, model=model, temperature=0, max_retries=0, timeout=15, extra_body={"models": [model] + fallback_models} if fallback_models else {}).with_structured_output(schema))
    if not candidates:
        raise ValueError("No valid LLM key found! Set GROQ_API_KEY or OPENROUTER_API_KEY in .env.")
    return candidates[0].with_fallbacks(candidates[1:]) if len(candidates) > 1 else candidates[0]


ioc_extractor_chain = ChatPromptTemplate.from_messages([
    ("system", "You are a Tier-3 SOC parser. Extract the primary IOC, classify its type ('ip', 'domain', or 'behavior'), and write a concise initial playbook search query."),
    ("human", "Raw Security Alert: {raw_alert}"),
]) | build_structured_llm_with_fallbacks(IOCExtractionSchema)

playbook_grader_chain = ChatPromptTemplate.from_messages([
    ("system", "You are a strict SOC Playbook Grader. Check if the retrieved playbook directly matches the alert and OSINT telemetry."),
    ("human", "Alert: {raw_alert}\nOSINT Data: {osint_data}\nRetrieved Playbook: {playbook_text}"),
]) | build_structured_llm_with_fallbacks(PlaybookGradeSchema)

mitre_rewriter_chain = ChatPromptTemplate.from_messages([
    ("system", "Translate this noisy security alert into formal MITRE ATT&CK technique names and IDs so vector search finds the exact playbook."),
    ("human", "Original Alert: {raw_alert}\nFailed Query: {current_query}"),
]) | build_structured_llm_with_fallbacks(MITRERewriteSchema)

report_generator_chain = ChatPromptTemplate.from_messages([
    ("system", "Generate a grounded SOC Incident Report strictly following the retrieved playbook and OSINT telemetry."),
    ("human", "Alert: {raw_alert}\nIOC: {extracted_ioc} ({ioc_type})\nOSINT Telemetry: {osint_data}\nRisk Score: {risk_score}/100\nContainment Action: {containment_status}\nGrounded Playbook: {playbook_text}"),
]) | build_structured_llm_with_fallbacks(IncidentReportSchema)
