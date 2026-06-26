# Rule Model

## LLM Security Evaluator

The evaluator uses pattern rules for:

- Instruction override attempts.
- Hidden prompt extraction.
- Jailbreak-style role play.
- Secret literals and internal network disclosure.
- Exfiltration intent.
- Risky Agent tool names and parameters.

Each finding has:

- `rule`: stable identifier.
- `severity`: low, medium, high, or critical.
- `evidence`: short matched excerpt.
- `recommendation`: defensive action.

The final risk level is derived from weighted severity scores.

## SOC Alert Triage

The triage prototype combines:

- Asset criticality.
- Event type weight.
- Confidence score.
- Tactic matches from the event payload.

The output is sorted by priority and includes evidence plus suggested next steps. This keeps the analyst workflow visible: why an alert was ranked, what tactic it resembles, and what should be checked next.

## Limitations

Rule-based systems are easy to audit but can miss novel phrasing, obfuscation, and context-dependent behavior. In production, these rules should be combined with normalization, enrichment, model-assisted review, and human validation.
