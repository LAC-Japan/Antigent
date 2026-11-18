---
name: deception-honeytoken
description: Common safety, targeting, marker, and evidence rules for the specialized artifact-path-decoy (S1) and in-environment-instruction (S3) strategies. Use with one of those skills, not as a third ambiguous strategy.
---

# Deception — common honeytoken rules

Use this rule set together with exactly one specialized deception strategy supported by
the scenario: `artifact-path-decoy` (S1) or `in-environment-instruction` (S3). Do not
use `deception-honeytoken` as the submitted `decision.strategy`; preserve the distinction
between factual artifacts and instructions so their effects can be evaluated separately.

## Shared eligibility
- Prefer first contact / reconnaissance and credential-access enumeration, when the
  attacker is still choosing where to go.
- Require an exact evidence-linked role and asset in `predicted_next`, an unused target,
  and a plausible post-apply delivery path. Prefer `predicted_next[0]`; during
  reconnaissance another exact predicted asset is eligible when the leading step
  has no exact safe action.
- Future read certainty is not required. A bounded, unused decoy attempt is preferable
  to indefinite inaction when its delivery path is plausible. Place it in the attacker-owned
  working copy observed in telemetry when the attacker has already copied the original. Without
  an exact target or plausible path, choose `no_intervention`; never guess an identity.
- A Skill documents policy, not capability. Use only operations explicitly advertised by
  the scenario adapter. Response diversion and honeypot diversion are not implied by this
  common rule set.

## Shared execution and evidence
- Submit exactly one strategy per action and set `decision.preempts` to the selected
  1-based `predicted_next` step (`predicted_next[0]` = 1; 0 is reactive only). Keep one
  active decoy per role; never overwrite or repeat it.
- Always pass a unique `marker` for later attribution. Use realistic secret-shaped values
  only for applicable S1 factual decoys; S3 uses a non-secret correlation ID. Do not expose
  decoy content, credentials, or marker values in summaries or sanitized evidence.
- Native apply/readback and exit codes establish only their own stages. Record attacker
  read/follow solely from subsequent attacker observations. An unread attempt is a valid
  diagnostic outcome, not evidence of read, decision change, or defense success.
- Keep the decoy consistent with nearby artifacts and observed behavior. Do not direct
  the attacker toward real protected assets or claim an isolated destination that does
  not exist.
