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
