# Project Trinetra (त्रिनेत्र)

Trinetra is an autonomous Tier-1 SOC incident triage and OSINT investigation
agent built with LangChain and LangGraph. It turns a raw alert into an
evidence-backed investigation, not just a chatbot response.

## What it does

1. **Structured alert parsing** - extracts the primary indicator and discovers
   additional IPs, domains, CVEs, and behavioral indicators from the same alert.
2. **Multi-indicator OSINT enrichment** - uses AbuseIPDB for IP reputation,
   domain intelligence for age and registrar signals, and CVE/EDR enrichment
   for vulnerability and behavior alerts. Every result identifies its source.
3. **Explainable risk scorecard** - calculates a 0-100 score from reputation,
   behavior, exposure, recency, and playbook context. It also reports confidence,
   rationale, and prioritized analyst actions.
4. **Adaptive MITRE RAG** - retrieves a local ChromaDB playbook, grades its
   relevance, and retries with a formal MITRE ATT&CK query when necessary.
5. **Safe containment** - scores of 80+ pause at a LangGraph `interrupt()` and
   require an analyst decision before the firewall tool can mutate state.
6. **Grounded synthesis** - produces a concise incident report with severity,
   MITRE mapping, indicators, containment status, remediation, and the full
   scorecard.

## Scorecard dimensions

| Dimension | Meaning |
| --- | --- |
| Reputation | Highest threat-intelligence confidence across indicators |
| Behavior | Presence of C2, phishing, encoded execution, or other malicious patterns |
| Exposure | Number of indicators requiring investigation |
| Recency | Risk from newly registered or recently observed domains |
| Context | Whether a relevant SOC playbook was found |

The score is deterministic and visible to the analyst; the LLM is used for
structured extraction and narrative explanation, not for silently changing the
decision threshold.

## AI engineering concepts demonstrated

- Typed structured outputs with Pydantic
- LangGraph state, conditional edges, cyclic retry, checkpointing, and HITL
- Provider fallback routing for resilient inference
- Local vector retrieval with a grounded relevance grader
- Deterministic guardrails around probabilistic model output
- Offline threat-intelligence fallbacks for demos and quota failures
- Evidence aggregation across multiple indicators

## Project structure

```text
trinetra.py            # Minimal CLI entry point
trinetra/
  config.py            # Project paths, .env loading, LangSmith pre-flight
  models.py            # Pydantic schemas, IOC discovery, scorecard
  osint.py             # OSINT and guarded containment tools
  llm.py               # Provider fallback router and structured LCEL chains
  graph.py             # Chroma retriever, LangGraph state and workflow nodes
  demo.py              # Demo scenarios and terminal report rendering
```

The package modules are reusable independently of the demo. For example, a
future API can import `build_trinetra_graph` without duplicating orchestration
logic or terminal-only code.

## Next expansion points

- Add passive DNS, certificate transparency, URL sandbox, WHOIS, and VirusTotal
  adapters behind the same indicator-enrichment interface.
- Persist investigations and analyst decisions in a case store.
- Add deduplication, alert correlation, campaign clustering, and temporal
  timelines across incidents.
- Add evaluation datasets for extraction accuracy, retrieval precision, score
  calibration, and remediation faithfulness.
- Expose the report through a small API/UI with scorecard filters and export.

## Run

The repository keeps runtime data locally under `data/` and loads `.env` from
the project directory, so it works even when launched from another directory.
ChromaDB is persisted in `data/chroma/` and reused on later runs.

On a new machine, run the one-line setup:

```bash
bash setup.sh
```

Then copy values into `.env` and start the demo:

```bash
.venv/bin/python trinetra.py
```

`setup.sh` creates an isolated `.venv`, installs `requirements.txt`, creates a
blank `.env` from `.env.example`, and prepares `data/chroma/`. No API values
are stored in the repository template.

The demo exercises critical C2, obfuscated PowerShell, and benign CDN paths.
