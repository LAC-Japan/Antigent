---
name: artifact-path-decoy
description: S1 factual decoy placed on a predicted artifact path. Use during reconnaissance of stored code or configuration when an exact evidence-linked artifact and plausible future access path exist.
---

# Artifact-path decoy (S1)

Place believable **factual content**, such as a configuration value or credential-shaped
honeytoken, on an artifact the attacker is predicted to access. Use
`decision.strategy="artifact-path-decoy"` and follow the common `deception-honeytoken`
rules. Do not mix imperative instructions into this strategy; use
`in-environment-instruction` instead when that is the mechanism being tested.

## Typed-action variant
- When the scenario's typed deception operation creates a previously absent file, it
  does not edit an existing artifact. This is only the **new-file variant** of
  S1 and must not be presented as validating decoys embedded in existing artifacts.
- Use the exact observed target identities the operation needs, and choose a previously absent path
  with a plausible post-apply access path named in `predicted_next`. Native identity
  resolution and readback belong to the adapter; never guess missing identities.
- Make the file name, format, and factual content consistent with the asset and the
  attack stage. Include the unique `marker` naturally in `content`; do not use explicit
  decoy/fake/honeytoken labels.
- **Up to 3 decoys per role**, each on a different previously absent path with its own
  unique marker. Choose a path that fits the observed layout and the predicted step.
- **Placement for discovery:** put the file where anyone reading the asset looks first: its
  top level, or a directory whose name says it holds secrets (for example `.secret/`), under
  an ordinary, commonly used file name. A file deep in the tree is found only by a
  deliberate search.
- Keep `content` short: at most 8 lines and 400 characters. A long file adds generation
  time and delays delivery.
- Never reuse a path you or the asset already have; the adapter refuses an existing
  path (exit 41) and the attempt still consumes the target. Track every planted path.
- Placing content can trigger the environment's own automation (for example a build).
  Consider that side effect in the
  rationale and subsequent observations. Native delivery remains distinct from attacker
  read, follow, decision change, and real-objective protection.

## Limits
Future read certainty is not required, but an unread new file is only an attempted and
possibly delivered decoy. Do not generalize its result to existing-artifact S1, response
diversion, or honeypot diversion.
