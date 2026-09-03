# Section 3 — Pipeline Gates and the Waiver Path

Workflow: [`.github/workflows/security-gates.yml`](../.github/workflows/security-gates.yml)

## Tools, one line each

| Layer | Tool | Rationale |
|---|---|---|
| SCA | Trivy | Consolidated with IaC: one binary, one vuln DB, one ignore format tied to our waiver file. |
| IaC | Trivy config + **Conftest** | Trivy for breadth; conftest carries our own rego for the §4b defect classes — the rules we actually got burned by. |
| SAST | Semgrep | Curated security rulesets with low noise; fast enough to run on every PR. |
| Secrets | Gitleaks | `fetch-depth: 0` + `gitleaks git` walks **every commit in history**, not the diff — a secret pushed and "removed" is still live until rotated. |

**What consolidation gave up:** Checkov's wider AWS rule catalogue and Semgrep's supply of
community IaC rules. Compensating control: the conftest rules encode exactly the
misconfigurations found in production here (public RDS, unencrypted storage, open SG,
gutted CloudTrail), with unit tests — depth on our actual failure modes over breadth.

## Blocking thresholds and the reasoning

- **Secrets: any finding blocks.** A credential is binary — it's exposed or it isn't; the
  fix (rotate + waive the fixture) is cheap and the miss is catastrophic (T3).
- **SCA: CRITICAL/HIGH *with a fix available*** (`--ignore-unfixed`). Blocking on unfixable
  CVEs trains 40 engineers to ignore the gate; unfixable criticals appear in the weekly
  report instead, and become blocking the day a fix ships.
- **SAST: ERROR severity from security rulesets only.** WARNING-level findings annotate the
  PR but never block — precision buys trust before recall (see enforcement posture,
  decisions doc).
- **IaC: CRITICAL/HIGH plus every custom conftest rule.** The custom rules block at any
  severity because each one maps to a named threat (T4) and has already occurred here.

## The waiver path (read: `waivers/waivers.yaml`, `scripts/waivers.py`)

- **Who approves:** the platform team, mechanically enforced — `/waivers/` is
  CODEOWNERS-gated, branch protection requires code-owner review. Approval is therefore a
  recorded PR review, not a Slack message.
- **Where it lives:** in-repo YAML, one file, versioned; scanners consume ignore files
  *generated from it* — nobody edits `.trivyignore` by hand.
- **Expiry:** mandatory, max 90 days. `scripts/waivers.py check` runs before any scanner
  and **fails every build on lapse**. Renewal is a fresh reviewed PR with fresh
  justification. No permanent waivers — permanence means changing the policy itself.
- **What lapse looks like:** main goes red for everyone, the error names the ticket and
  the owner. Lapse is deliberately louder than the original finding.

## Break-glass

One path, for production-down only: `docs/03-break-glass.md`.

## Expected false-positive load, and what gets tuned first

Honest expectation: **Trivy OS-package CVEs dominate** (dozens per base image, mostly
no-fix) — tuned first, via `--ignore-unfixed` (already on) and the distroless base the
Dockerfile already uses. Second: **Gitleaks shape-matches on secret *references*** —
confirmed on this repo's first real CI run: rule `kubernetes-secret-yaml` fired on the
ExternalSecret manifest, which holds only a Secrets Manager path, no material. Waived
by fingerprint through the waiver file (SEC-151), never via inline comments — the
waiver path in this submission has processed a real finding, not just an example.
Third: **Semgrep generic-crypto/audit rules** — we start from `p/security-audit` at ERROR,
and demote individual noisy rules by id in the waiver file so every demotion is reviewed
and expiring. Target steady state: a merge blocked by the gates is *actionable* >80% of
the time, measured by waiver-vs-fix ratio per month; if waivers outnumber fixes, the
threshold is wrong, not the engineers.
