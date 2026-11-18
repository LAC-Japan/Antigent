---
name: in-environment-instruction
description: S3 bounded defensive instruction placed in an environment artifact the attacker is predicted to read. Use to test instruction following and decision change separately from factual honeytokens.
---

# In-environment instruction (S3)

Place a short, plausible **instruction** in an environment artifact on a predicted access
path. Use `decision.strategy="in-environment-instruction"` and follow the common
`deception-honeytoken` rules. Do not mix factual credential/configuration decoys into the
same action; that would confound S1 and S3 attribution.

## Typed-action variant
- Use the scenario's typed deception operation with exact observed target identities and a
  previously absent path that has a plausible post-apply access path in `predicted_next`. This operation
  does not modify an existing artifact.
- Keep the instruction consistent with the surrounding content and the defensive
  objective. Include the unique, non-secret `marker` naturally as a correlation ID without
  making it a credential/configuration value or identifying the file as a decoy or test.
- Instructions must be bounded and reversible: direct only to a benign verification or
  the delivered decoy artifact. Never request destructive actions, real credential use,
  changes to real protected assets, or access to an unimplemented honeypot/route.
- Native readback establishes delivery only. Determine instruction following or decision
  change exclusively from later attacker observations and the independent evaluator.

## Limits
Future read certainty is not required. A delivered but unread instruction is not a
followed instruction or a defense success. Do not claim response diversion, isolated
honeypot containment, or existing-artifact S3 without the corresponding native
capability and evidence.
