# AI-Assisted SOC Alert Triage Prototype

This project simulates a small SOC triage assistant. It ingests JSONL alerts, calculates priority, maps events to attack semantics, and generates concise analyst notes.

## Covered Scenarios

- Web attack attempts such as SQL injection and suspicious framework probes.
- Reverse shell or outbound connection indicators.
- Abnormal login and credential events.
- Sensitive file access and webshell-like file writes.
- Noise reduction for low-confidence scanners.

## Run

```bash
python src/triage.py --input data/alerts.jsonl --top 5
python src/triage.py --input data/alerts.jsonl --format json
```

## Output Fields

- `priority`: numeric score for sorting.
- `severity`: low, medium, high, or critical.
- `tactics`: MITRE-style high-level tactics.
- `summary`: analyst-friendly event description.
- `next_steps`: recommended verification and response actions.

This is designed as a transparent baseline that can later be connected to an LLM for report generation, case clustering, or analyst Q&A.

