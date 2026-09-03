# Section 2 — Build and Release Integrity (T1, T5)

Pipeline: [`.github/workflows/build-release.yml`](../.github/workflows/build-release.yml)

## The one-line justifications the brief asks for

- **Keyless signing, not keyed:** a 2-person platform team should not carry long-lived
  signing-key custody; the trust root is the Sigstore public-good TUF root plus GitHub's
  OIDC issuer, and verification pins the exact repo + workflow identity. Accepted
  trade-off: repo/workflow metadata becomes public in the Rekor transparency log.
- **OIDC sub scoping** (`iam/oidc-trust-policy.json`): `sub` is pinned to
  `repo:mal-bank/accounts-api:environment:production`. **What that denies:** forked
  repos, pull_request runs, any other repo in the org, any branch/workflow that has not
  passed the `production` environment's required-reviewer gate (platform team) — i.e.
  40 people can merge code, but none of them can mint AWS credentials from an arbitrary
  workflow run. This is the primary T1 containment. One rollout caveat, checked against
  current GitHub docs: repositories created after 15 Jul 2026 present an immutable,
  ID-qualified `sub` (owner and repo IDs embedded), so the condition is pinned to the
  sub observed in the first real token, not the name-based form shown here for
  legibility.
- **Registry mapping:** this submission's pipeline pushes to ghcr.io (free tier) and
  demonstrably runs end-to-end there; production is ECR in ap-south-1 with the same
  controls — registry-enforced immutability (`terraform/ecr.tf`) and digest-only
  consumption.
- **Tag immutability:** tags are `sha-<commit>` / semver, `latest` is never pushed.
  Registry-side: ECR `image_tag_mutability = "IMMUTABLE"` (see `terraform/ecr.tf`), so a
  push to an existing tag is rejected by the registry, not by convention. Belt-and-braces:
  deploy manifests and admission policy consume **digests**, so even a mutated tag would
  deploy nothing.
- **SBOM as attestation, not artifact:** attached to the image digest and co-signed, so it
  survives log retention, travels with the image, and is verifiable by anyone holding the
  digest — a build-log artifact is none of those.

## What the signature proves / does not prove

Proves: this digest was built by this workflow file in this repo from the recorded commit,
unaltered since. Does **not** prove: the code is safe, a human reviewed it, dependencies
are clean, or the runner wasn't compromised. A maintainer-account takeover still produces
a validly signed malicious image (worked in the decisions doc, blast radius b). Reviewers
should read the signature as pipeline integrity, not code assurance.

## Known limitation, recorded honestly: the verify job's live-Sigstore dependency

The signing and attestation steps run green (`build-sign-attest`): the image is built,
keyless-signed, and SBOM-attested, with the Rekor entry created. The separate `verify`
job, however, performs **keyless verification against Sigstore's public-good
infrastructure** (TUF trust-root fetch, Fulcio cert-chain check, Rekor inclusion-proof
lookup) on every run. In this repo's CI that verification **stalled** — and cosign's own
`--timeout` did not bound it, because the stall is in the TUF/network setup phase outside
the operation timeout. I hardened the job to wrap each cosign call in an OS-level
`timeout` with retries and a TUF pre-warm, so it now either completes, tolerates a
transient stall, or **fails fast and blocks the release** rather than hanging. It may
still go red when Sigstore's public endpoints are slow — that is an availability
dependency, not a break in the signing chain.

**What I'd do with more time (the bank-grade fix):** stop verifying against live public
Sigstore in the release path. Sign with a **cosign bundle** so the Rekor inclusion proof
and certificate travel *with* the artifact, then verify **offline** (`cosign verify
--offline`) against a **pinned, mirrored trust root**. That removes the external
dependency entirely, makes verification deterministic and fast, and is the posture a
regulated bank should run anyway — a release gate must not depend on a third party's
uptime. The same pinned-root verification is what `verify-image-signature.yaml` would use
at admission. This is deferred, not designed away; it maps to **T1** exactly as the live
verification does.
