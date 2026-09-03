# Break-glass: shipping through red gates during a production-down incident

**Scope:** production is down or actively degrading and the fix cannot pass gates in time
(scanner outage, upstream registry down, a gate blocking the hotfix itself). Not for
"the deadline is today." Invoking it for convenience is a conduct issue, not a tooling
gap — the trail below makes that visible.

## The path (one, and only one)

1. Declare the incident (page platform on-call; open incident channel + ticket `INC-n`).
2. Trigger `security-gates.yml` via **workflow_dispatch** with `break_glass=true` and
   `break_glass_reason=INC-n: <one line>`. A missing reason fails the run.
3. The run pauses on the **`break-glass` GitHub environment**, which requires approval
   from a platform-team member *other than the person dispatching* (two-person rule;
   with a 2-person platform team that means both of them — accepted cost).
4. On approval, scanner jobs are skipped; build-release still runs, so the emergency
   image is **still signed, still SBOM-attested** — break-glass skips *gates*, never
   *provenance*.
5. Deploy proceeds through the normal `production` environment.

## The audit trail it leaves (all timestamped, none deletable by the actor)

- GitHub **environment approval log**: who approved, when (org audit log, 400-day
  retention; streamed to the SIEM in production).
- The **workflow run** itself: actor, reason input, commit SHA, skipped jobs visible.
- An **auto-created issue** labelled `break-glass, security-debt` recording actor, run
  URL, and reason — with a 72h SLA to re-run gates green; the issue pages platform if it
  breaches.
- The deployed image's **signature certificate** encodes the exact workflow run, so the
  artifact itself is traceable to the bypass forever.

## Closing the loop

Within 72h: gates must pass on a follow-up run against the shipped commit (or a waiver
must land through the normal reviewed path), and the issue is closed with a link to the
green run. Break-glass frequency is reported monthly; more than ~1/quarter means the
gates are mis-tuned and get revisited (see false-positive note in
`03-gates-and-waivers.md`).
