# accounts-api — security engineering take-home

Securing `accounts-api`: a containerised REST service over customer account data on a
shared EKS cluster in ap-south-1, built by GitHub Actions into a multi-account AWS org.
Everything traces to the threat model (T1–T5) in `docs/01-threat-model.md`.

## Running the policy tests (the part a reviewer verifies)

Committed outputs live in [`test-output/`](test-output/); to reproduce:

```bash
# Kyverno — admission baseline. Expect 34/34: the in-production manifest
# (artifact a, verbatim) rejected rule-by-rule, the fixed manifest clean, and
# a fixture of bypass attempts (initContainer violations, RoleBinding to
# cluster-admin, foreign registry) rejected too.
brew install kyverno   # or the kyverno-cli release binary
kyverno test policy/kyverno/tests/

# Conftest — Terraform rules. Unit tests encode fail-before/pass-after,
# including evasion shapes (inline/dynamic SG blocks, IPv6, Aurora, vars).
brew install conftest
conftest verify --policy policy/rego                                        # 21/21
conftest test --parser hcl2 --policy policy/rego policy/terraform-fixtures/bad.tf   # artifact (b): MUST fail (9 denies)
conftest test --parser hcl2 --policy policy/rego remediate/terraform/ terraform/    # fixed: MUST pass

# Terraform — fixed config validates (nothing is applied, per the brief)
cd remediate/terraform && terraform init -backend=false && terraform validate
```

CI runs the same commands (`.github/workflows/security-gates.yml`, jobs `iac` and
`admission-policy-tests`), so the fixtures are enforced, not decorative.

## Map: brief section → artifacts

| Section | Files |
|---|---|
| 1 Threat model | `docs/01-threat-model.md` |
| 2 Build integrity | `.github/workflows/build-release.yml`, `iam/oidc-trust-policy.json`, `terraform/ecr.tf`, `docs/02-build-integrity.md` |
| 3 Gates + waivers | `.github/workflows/security-gates.yml`, `waivers/waivers.yaml`, `scripts/waivers.py`, `.github/CODEOWNERS`, `docs/03-gates-and-waivers.md`, `docs/03-break-glass.md` |
| 4 Review & remediate | `remediate/`, `iam/pod-identity-policy.json`, `policy/kyverno/`, `policy/rego/`, `policy/terraform-fixtures/bad.tf`, `docs/04-remediation.md` |
| 5 Admission & runtime | `policy/kyverno/`, `runtime/falco-rules.yaml`, `runtime/runbook.md`, `network/egress.yaml`, `docs/05-admission-runtime.md` |
| 6 Secrets & data | `secrets/external-secrets.yaml`, `iam/eso-policy.json`, `docs/06-secrets-rotation.md`, `docs/06-log-redaction.md` |
| Part 2 Decisions | `docs/07-decisions.md` |

## The pipeline runs for real

The brief says the service can be assumed to exist; `app/` + `Dockerfile` are a minimal
stand-in (one static Go binary, distroless, non-root) so the supply chain is
**executable, not aspirational**: the `build-release` workflow in this repo actually
builds, pushes to ghcr.io, generates and attests the SBOM, keyless-signs, and then
*verifies* its own signature and attestation as a required job — check the Actions tab
for green runs. The stub also makes the runtime story concrete: a single-binary,
no-shell image is the assumption the Falco rules and admission baseline depend on.

The security gates run against this repo itself, and the first real run produced a
real finding: gitleaks' `kubernetes-secret-yaml` rule fired on the ExternalSecret
manifest — a false positive (it holds a secret *reference*, not material) — which was
waived by fingerprint through `waivers/waivers.yaml`. The waiver path has processed
a genuine finding, not just the worked example.

## Assumptions (the one-liners)

Org/repo `mal-bank/accounts-api`; account `123456789012`; private EKS endpoint,
v1.29+, IRSA in use; event stream = Kinesis; audit records = append-only Firehose;
branch protection with required reviews + required `security-gates` checks is
configured (repo settings, recorded in `.github/CODEOWNERS` header); example ARNs/CIDRs
are placeholders and marked where they appear.

No real cloud was used or required: kyverno/conftest/terraform validate ran locally;
where AWS would be applied, the file says so and moves on.
