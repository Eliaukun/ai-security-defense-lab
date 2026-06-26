# AI Security Defense Lab

AI Security Defense Lab is a small Python security lab for evaluating LLM application risks and triaging security alerts with transparent, auditable rules.

The repository contains two independent but related prototypes:

- `llm-rag-agent-security-eval`: evaluates prompt injection, RAG poisoning, sensitive data exposure, and risky Agent tool calls.
- `ai-soc-alert-triage`: ranks SOC alerts, maps events to attack tactics, and generates analyst-oriented response notes.

The code uses local sample data and standard Python libraries, so it can be reviewed and run without private datasets, API keys, or offensive infrastructure.

## Design Goals

- Keep detection logic explicit and easy to audit.
- Model LLM application security as a system problem, not only a prompt problem.
- Provide reproducible sample cases for both AI security evaluation and SOC triage.
- Avoid handling real secrets, private telemetry, or live offensive infrastructure.

## Repository Layout

```text
.
|-- llm-rag-agent-security-eval/
|   |-- README.md
|   |-- data/
|   |-- src/
|   `-- tests/
|-- ai-soc-alert-triage/
|   |-- README.md
|   |-- data/
|   |-- src/
|   `-- tests/
|-- docs/
|   |-- design-notes.md
|   `-- rule-model.md
`-- README.md
```

## Quick Start

Run the LLM security evaluator:

```bash
python llm-rag-agent-security-eval/src/evaluator.py --input llm-rag-agent-security-eval/data/cases.json --format table
```

Run SOC alert triage:

```bash
python ai-soc-alert-triage/src/triage.py --input ai-soc-alert-triage/data/alerts.jsonl --top 5
```

Run tests:

```bash
python -m unittest discover -s llm-rag-agent-security-eval/tests
python -m unittest discover -s ai-soc-alert-triage/tests
```

## Safety Boundary

This repository is for defensive research and controlled testing. The sample cases are synthetic and intentionally limited. The tools do not exploit real systems, connect to external targets, collect credentials, or automate unauthorized access.
