# Scenario context — cicd-goat

Returned to Antigent by `describe_scenario`. Target-specific knowledge lives here, so
`AGENTS.md` and the skills stay generic.

## Knowledge boundary
This file describes only the defended environment: what runs where, how it is configured, what
each sensor records, and which actions the adapter supports. It deliberately contains no attack
path, no list of weaknesses and no expectation of what an attacker will do. Infer intent and
next steps from the events you observe.

## Environment (defended configuration)
- **gitea** — source server. Hosts the organisation's repositories (for example the `Wonderland`
  organisation); repositories carry their CI configuration as a `Jenkinsfile`.
- **jenkins** — CI controller. Builds pipelines from the Gitea repositories (multibranch jobs that
  scan Gitea for branches and pull requests), stores credentials for those pipelines and has a
  script console.
- **prod** — deploy host that pipelines reach over SSH. Its web root is
  `/var/www/localhost/htdocs/`.
- **ctfd** — an unrelated service in the same range. It is observe-only: you cannot act on it.

## What the sensors record
- gitea: its router access log (`Started` / `Completed <method> <path> <status>` with the client
  address). Request paths have their usual Gitea meaning: `/api/v1/repos/search` and
  `/explore/repos` = repository search; `.git/info/refs?service=git-upload-pack` and
  `POST .git/git-upload-pack` = clone or fetch; `.git/info/refs?service=git-receive-pack` and
  `POST .git/git-receive-pack` = push; `/repo/fork/<id>` = fork; `POST /api/v1/repos/<owner>/<repo>/pulls`
  = pull request created; `/user/sign_up` = account registration; `/user/login` and
  `/api/v1/user` = sign-in and the signed-in user. Failed sign-ins appear as `auth-failure` /
  `auth-burst`. Repository content read by an outside client (clone/fetch, or a file through the
  API or raw URL) is additionally reported as `repo-read` and starts a turn at once.
- jenkins and ctfd write no access log. With the netsensor their HTTP requests appear as
  `net-http` (source `jenkins` or `ctfd`). Jenkins paths: `/api/json`, `/view/`, `/job/<name>/` =
  item listing and pages; `POST /j_spring_security_check` followed by `/loginError` = failed form
  login (not a 401); `/script`, `/scriptText` = script console; `/credentials/` = credential store;
  `/job/<name>/build` = build trigger. A request for `/job/<name>/` shows only the requested path,
  not that such a job exists.
- Jenkins' own build and branch-indexing log is not shown, except builds of pull requests:
  `pipeline-run` (source `jenkins`) marks such a build being scheduled or finishing, and its `job`
  field is the exact WorkflowJob full name (`<multibranch job>/PR-<n>`, usable as `job_full_name`).
  It names the build, not who submitted the pull request.
- prod: filesystem changes (`docker diff`) appear as `fs-change`.

## Typed actions
- Gitea deception: `{role:"gitea", operation:"gitea_repo_file", repository:"owner/repo", ref:"main", path:"relative/file", content:"...", marker:"...", evidence:[event_index]}`.
  The `marker` value must appear verbatim in `content`; otherwise the adapter refuses the operation
  before any change, and that target still counts as used.
- Jenkins containment: `{role:"jenkins", operation:"jenkins_disable_job", job_full_name:"exact/job", evidence:[event_index]}`.
- Skill mapping: `gitea_repo_file` is the deception operation (used by `artifact-path-decoy` and
  `in-environment-instruction`); `jenkins_disable_job` is the containment operation and disables one
  WorkflowJob. A new file on a repository's default branch can make Jenkins re-index that repository's
  multibranch job and start a build.
- The adapter performs native delivery/containment readback. For Gitea it first resolves owner/repository
  casing against exactly one native bare repository; zero or ambiguous matches fail before mutation. Refs,
  paths and Jenkins job identities remain exact. Raw `cmd` is refused; do not retry a mutating attempt in
  the same turn. The driver links post-apply reobservation itself (no extra turn) and runs a final
  reobservation turn after the attack.

## Strategy capabilities and action eligibility
- One typed action per observation, deduplication, serial reobservation, native receipts, final
  reobservation and recovery apply; there is no fixed limit on the number of attempts.
- **Available deception strategies:** choose exactly one per Gitea action:
  - `artifact-path-decoy` (S1): factual decoy content in a previously absent repository file. This
    is only the new-repository-file variant; the adapter does not implement existing-artifact S1.
  - `in-environment-instruction` (S3): a bounded defensive instruction in a previously absent
    repository file. Do not mix factual credential/configuration decoys into the same action.
  - `deception-honeytoken` supplies common rules for both and is not a third submitted strategy.
- **Unavailable strategies:** S2 `response-diversion` remains pending and S4 `honeypot-diversion`
  has no isolated destination, delivery adapter, or arrival evaluator. Do not select or claim them.
  `containment` provides only exact single-WorkflowJob disable/final-check/recovery, not graduated S5.
- The deterministic run context is historical data. A clone, fetch or raw-file request proves a read
  at that event only; it does not prove that a later defense commit was read. Internal Jenkins scans,
  defense apply/readback, native delivery and exit 0 are not attacker read/follow evidence.
- For action eligibility, `predicted_next` must name an exact evidence-linked target and a plausible
  post-apply delivery path; future read certainty is not required. Prefer `predicted_next[0]`, but
  during reconnaissance another exact predicted repository is eligible when the leading step has no
  exact safe action. If the selected step is a Jenkins login, a Gitea file is not a plausible delivery
  surface for that step. Without an exact target or plausible path, choose `no_intervention`.
- Never guess a repository, ref or job identity; use exact observed identities and native receipt
  history. For `gitea_repo_file`, the defender selects a previously unused relative `path` consistent
  with the observed repository layout; do not claim that this new path was observed or already exists.
  Do not repeat a used target even when its attempt failed before apply. Missing refs, existing paths,
  parent folders and snapshot failures are not new opportunities.
- `decision.preempts` is 1-based: `predicted_next[0]` = 1, while 0 is reactive only.
- `gitea_repo_file` creates a previously absent file; it does not overwrite an existing file. A
  bounded unread attempt is an eligible diagnostic outcome, not attacker read/follow or defense success.
- For `jenkins_disable_job`, use an exact evidence-linked WorkflowJob, not its parent folder. Native
  delivery or containment and subsequent attacker read/follow remain separate evidence stages.

## Routine internal traffic (not the attacker)
- jenkins-server regularly scans the Wonderland repos through the Gitea API
  (`/api/v1/repos/Wonderland/<repo>`, `/branches`, `/pulls?state=open`, raw Jenkinsfile) and
  re-indexes the multibranch jobs. These come from the range's own containers and are
  filtered out of new-source / recon-burst; do not read them as reconnaissance.
