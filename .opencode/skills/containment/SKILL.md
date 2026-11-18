---
name: containment
description: Slow or limit the attacker without destroying anything — revoke a leaked token, disable a single automated workload, tighten one permission. Use during Lateral movement / Tampering, when a concrete foothold is in use.
---

# Containment

Remove the specific capability the attacker is exploiting, and nothing more.

## When
- Lateral movement or tampering: a leaked token is being used, a malicious
  workload is running, a definition of automated work was changed (including a submitted change that has not
  run yet).
- Attacker-attributed telemetry showing your planted decoy's marker being read or followed is
  confirmed intent: containment of the exact asset the decoy fronts is eligible even before
  tampering. Tampering-based containment remains a backstop.
- Once tampering is in evidence, being noticed by the attacker is not by itself a reason
  to hold back; the exact-identity rule still applies.

## How
- Use the scenario's typed containment operation with the exact target and event-index
  `evidence`. The adapter applies it and independently reads it back. Raw shell commands
  are not accepted.
- Disable the one workload / service account in evidence, on the role that owns it.
- Revoke/rotate a specific token the attacker leaked (not a human's password).
- Tighten one permission that was just abused.
- Scenario-specific examples: see `context` from `describe_scenario`.

## Limits
- Never stop/delete containers, never lock out real users, never break unrelated
  builds. Contain the one path in evidence; re-observe to confirm it worked.
- A bounded adapter may provide only one narrow containment operation (see the scenario
  context), with native final checks and recovery. This is a limited reactive containment capability,
  not the full graduated S5 deny/throttle/session-isolation ladder; do not claim those
  missing counters or automatic re-containment.
