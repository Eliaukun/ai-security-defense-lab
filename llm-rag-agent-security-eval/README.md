# LLM RAG/Agent Security Evaluation Toolkit

This project is a lightweight security evaluator for LLM applications. It focuses on risks that appear when a model is connected to retrieval content, internal knowledge bases, or Agent tools.

## Covered Risks

- Prompt injection and instruction override attempts.
- Jailbreak-style role play and safety bypass prompts.
- Sensitive data exposure such as tokens, private keys, cookies, and internal hosts.
- RAG poisoning indicators in retrieved documents.
- Risky Agent tool calls, especially network, file, and command execution operations.

## Run

```bash
python src/evaluator.py --input data/cases.json --format table
python src/evaluator.py --input data/cases.json --format json
```

## Design Notes

The evaluator uses transparent rules instead of a black-box model. This makes the results easy to audit in interviews and easy to extend later with an LLM judge, embedding similarity, or a policy engine.

Recommended production hardening ideas:

- Separate instructions from untrusted retrieved data.
- Run permission filtering before retrieval instead of after generation.
- Add tool allowlists, parameter validation, approval gates, and full audit logs.
- Redact sensitive values before they enter model context.
- Evaluate both model output and tool-call traces.

