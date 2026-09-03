# Part 2 — Decisions and Trade-offs

## Biggest decisions

**1. Identity is the perimeter: OIDC sub-scoping + keyless signing + digest-pinned
deploys (T1).** With 40 people merging and 2 on platform, I spent the budget on making
*credential issuance* narrow (only the `production` environment gate mints AWS creds)
and *artifact identity* verifiable end-to-end (sign → attest → verify at admission).
Trade-off: Sigstore's public infrastructure is now in the trust chain and build
metadata is public in Rekor; accepted, because the alternative — key custody by two
people — fails worse and quieter.

**2. Deleting the service's Kubernetes RBAC instead of narrowing it (T2).** The
easy fix was scoping the wildcard Role; the right fix was noticing the service needs
zero API access once ESO delivers its secret. Trade-off: a hard dependency on the ESO
controller for secret delivery — if ESO breaks, secret refresh stalls (existing mounts
keep working, so it degrades slowly, and it pages).

**3. A place I chose NOT to enforce: admission policies run cluster-wide in Audit,
enforced only in `accounts`, day one.** Enforcing the baseline on ~12 other teams'
workloads by fiat would break unknown workloads, burn the trust the gates depend on,
and get the webhook itself turned off within a month — the same failure mode as a gate
with no waiver path. **Compensating controls while cluster-wide is audit-only:**
PolicyReports reviewed weekly with owners named, per-namespace promotion on a published
schedule, and the highest-consequence policy (signature verification) enforced where it
matters most from day one. Same posture at runtime: Falco detects, it does not kill —
on a regulated ledger service I want a human deciding to break availability, so the
compensating control is a rehearsed sub-15-minute quarantine+rotate runbook rather than
an automated response.

## Enforcement posture

**Block on day one:** secrets (any finding, full history); SCA CRITICAL/HIGH with fix
available; custom conftest IaC rules (each maps to a defect that already shipped);
waiver expiry; admission baseline in `accounts`; signature verification in `accounts`.
**Warn on day one:** SAST below ERROR; Trivy IaC below HIGH; all admission policies in
other namespaces; `disallow-secrets-from-env` everywhere.
**Promotion sequence:** warn → announce with date → block, per gate per namespace.
**Evidence a gate is ready:** 14 consecutive days of zero (or all-waived) findings at
the target threshold, waiver-to-fix ratio < 1 for the month, and zero break-glass
invocations attributable to that gate. A gate promoted without that evidence is
promoted on hope.

**Branch protection is enabled on this repository, not merely described:** `main`
requires all six `security-gates` checks to pass, requires a pull request before
merging, blocks force-pushes and deletions, and is enforced on admins. A demonstration
PR that reintroduces the T4 public-database defect is left open as evidence — its `iac`
check fails and the merge is refused by policy. One honest accommodation for a
single-maintainer repo: required approvals are set to 0 and code-owner review is off,
because a lone author cannot approve their own PR and the `CODEOWNERS` team is
illustrative. In a real org both flip on with the actual two-person platform team; the
`CODEOWNERS` file and the waiver-approval story already assume it.

## Blast radius

**(a) accounts-api compromised via RCE.**
*Reaches:* the pod — its DB credential file (full read/write of customer PII via the
app user), the Kinesis stream, the KYC egress path, its own memory.
*Denied by design:* node takeover (no docker.sock/hostPath/hostNetwork, non-root,
seccomp, caps dropped); other teams' secrets (RBAC deleted; SA token not even
mounted); AWS lateral movement (pod role: one secret path, one stream, append-only
audit — no IAM verbs); arbitrary exfil (egress: proxy to one FQDN); persistence via
image swap (digest-pinned, signature-verified).
*Evidence afterwards:* Falco process/credential-read events, proxy CONNECT logs,
CloudTrail for the pod role, RDS pgAudit, quarantined pod filesystem.
*Where evidence goes dark:* inside the process — in-memory abuse of the *legitimate*
DB session (queries within the app user's normal grants) looks like the app working.
pgAudit shows queries but not intent; low-and-slow reads through the app's own access
pattern are the dark zone (see detection gap).

**(b) Maintainer's GitHub account taken over, workflow file modified.**
*Reaches:* the repo and CI. The attacker can open PRs, and with a second stolen
approval merge a malicious workflow; a merged workflow on a protected branch can
reach the `production` environment gate.
*Denied by design:* direct credential theft from a PR run (OIDC sub requires the
`production` environment — pull_request and fork runs can't mint creds);
silent tag mutation (ECR immutable + digest deploys); unsigned images in prod
(admission verifies the exact workflow identity — a *different* workflow file path
fails verification); waiver/policy tampering without a platform reviewer
(CODEOWNERS on `/policy/`, `/waivers/`, `/.github/workflows/`).
*What still succeeds — honestly:* a takeover of a **platform** member plus one more
approval gets a validly signed malicious build through `build-release.yml` itself;
the signature then attests to the compromise faithfully.
*Evidence:* GitHub audit log (auth anomalies, workflow edits), environment approval
records, Rekor entry binding the artifact to the exact commit and run, CloudTrail
AssumeRoleWithWebIdentity with the repo/ref in the session context.
*Goes dark:* between merge and deploy — a malicious but not-yet-deployed workflow
sits quietly; nothing pages on "workflow file changed" today (closable: alert on
diffs to `.github/workflows/` outside release cadence — cheap, on the Monday list).

## Detection coverage — the named gap

**Low-and-slow PII harvesting through the application's legitimate access path** —
valid credentials or the RCE above, reading customer records at plausible rates via
normal queries. Nothing I built distinguishes it from production traffic: Falco sees
the expected process, the proxy sees the expected destination, pgAudit sees the
expected user making expected-shaped queries. **Cost to close:** per-request access
accounting joined across ALB → app audit records → pgAudit, plus a behavioural
baseline (records/customer/session, distinct-account fan-out per principal) — realistic
build: 2–4 engineer-weeks plus ongoing tuning, or a database activity monitoring
product. It's the first *detection* investment I'd make after this submission, and it's
why the audit write path is append-only IAM — those records are the input it needs.

## Regulatory framing

| Control (built here) | Obligation it serves |
|---|---|
| Multi-region, validated, KMS-encrypted, org CloudTrail (§4b) | Audit trail integrity — examiner can rely on logs; tamper-evidence via digest validation |
| IAM grants and KMS use condition-pinned to ap-south-1 services/ARNs (§4c, §6); the org-level SCP is named in the cut list, not claimed | Data residency (RBI data-localisation for payment data in India) |
| RDS 30-day PITR + final snapshot + deletion protection; trail bucket Object Lock (§4b) | Retention and recoverability of records |
| Least-privilege pod IAM + deleted RBAC + CODEOWNERS gates (§4c, §3) | Access control and periodic access review — reviewable because it's small and in git |
| Only last-4 stored; allowlist logging + PAN scrubber (§6) | Cardholder-data scope minimisation (PCI DSS) — keeps full PAN out of systems and logs |
| Falco→PagerDuty with owned runbook + append-only audit records (§5) | Breach detection and notification readiness — evidence and timeline exist within the reporting window |

## What you cut, and Monday morning

**Cut for time:** distroless/minimal base image work (biggest FP-load reducer);
DAST; the rotation lambda's code (mechanism specified, not implemented); CoreDNS
egress rate-limiting; SCPs pinning the org to ap-south-1 (stated as residency control,
not authored); Cilium/FQDN-aware CNI evaluation; workflow-diff alerting.
**First thing Monday:** apply the admission policies to the real cluster in the
committed Audit/Enforce split and let PolicyReports start accumulating — every other
control here gets *stronger* with that evidence stream, and it's the one that protects
eleven other teams, not just this service. Second: the workflow-diff alert, because
blast-radius (b) showed it's cheap and currently dark.

**Recorded as a known fail, not hidden:** the release pipeline's `verify` job depends on
live Sigstore public infrastructure and stalled in CI; I bounded it to fail-fast rather
than hang, but did not make it reliably green. The right fix — offline cosign-bundle
verification against a pinned, mirrored trust root — is written up in
`docs/02-build-integrity.md` and is genuinely the bank-grade approach (a release gate
must not hinge on a third party's uptime). I chose to document this honestly and spend
the remaining budget on the security design rather than on chasing external-infra
flakiness, since the signing chain itself (`build-sign-attest`) is green and the gap is
operational, not a break in provenance.
