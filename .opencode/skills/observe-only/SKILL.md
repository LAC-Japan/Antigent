---
name: observe-only
description: Deliberately hold back and keep watching. Use when evidence is weak or ambiguous, or when an intervention would reveal the defender without stopping a real threat. This is a legitimate, often optimal choice.
---

# Observe-only (no_intervention)

Not every event deserves a response. Premature action teaches the attacker that a
defender is present and wastes a honeytoken's surprise.

## When
- Confidence is low because there is no exact evidence-linked target or no plausible
  post-apply delivery path, or an existing decoy already covers the predicted step.
- Do not choose inaction merely because a future decoy read cannot be guaranteed. An
  eligible, bounded, unused decoy attempt is preferable to repeated observation without
  any deception trial during reconnaissance.

## How
- `submit_turn` with `decision.strategy = "no_intervention"`, a one-line rationale, and
  no actions. Keep observing; raise confidence before acting. Never guess a target, and
  never convert a predicted or delivered decoy into attacker read/follow evidence without
  subsequent attacker observations.
