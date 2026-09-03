# Section 4 — Review and Remediate

Ranking is by **exploitability in this environment** (internet-facing API, shared cluster,
40 committers), not scanner severity. Fixed artifacts: `remediate/`. Prevention —
the graded part — is policy-as-code with fail-then-pass fixtures:
`policy/kyverno/` (workload) and `policy/rego/` (Terraform), both run in CI and
locally (see README).

## 4a — Workload manifest (fixed: `remediate/workload-fixed.yaml`)

| # | Defect | Why it ranks here (exploitability) | Fix | Prevented by |
|---|--------|-------------------------------------|-----|--------------|
| 1 | `docker.sock` hostPath mount | Any RCE in the container (T2/T5) becomes **node root** with one `docker run --privileged` against the socket — no exploit needed, and the node hosts other teams' workloads. `privileged: false` is irrelevant. | Mount deleted | `disallow-hostpath` |
| 2 | `hostNetwork: true` | Pod lives in the node's netns: reaches kubelet (10250) and node-local services, sidesteps NetworkPolicy — lateral movement on a shared cluster. | Removed | `disallow-host-namespaces` |
| 3 | RBAC `secrets,pods,configmaps` × `verbs: *` | Post-RCE, the SA token reads **every secret in the namespace** and can create/delete pods — credential theft plus persistence via the API even after the pod is rebuilt. | Role **deleted** (service needs zero K8s API; ESO delivers the secret) | `restrict-rbac-wildcards` |
| 4 | `runAsUser: 0` | Root amplifies #1/#2/#7 and makes container-filesystem tampering trivial. | `runAsNonRoot: 10001`, seccomp RuntimeDefault, drop ALL caps, RO rootfs | `require-run-as-nonroot` |
| 5 | `image: …:latest` | Whoever can push the tag owns prod at next restart, silently; no rollback identity, defeats signing (T1). Needs push access, hence below the post-RCE items. | Digest-pinned reference from the signed build | `require-image-digest`, `verify-image-signature` |
| 6 | `envFrom: secretRef` | Creds leak via `/proc/<pid>/environ`, crash dumps, child processes, debug endpoints. | Secret mounted as read-only file | audit-mode policy `disallow-secrets-from-env` |
| 7 | writable hostPath `/var/log` | Tamper with **node** logs as root — evidence destruction (regulatory), symlink tricks against log shippers. | Removed; stdout logging | `disallow-hostpath` |
| — | Also absent: resource limits, probes, `automountServiceAccountToken: false` | Noisy-neighbour DoS on a shared cluster; a mounted SA token it never uses. | All added | limits policy ships audit-mode |

The policies also reject the evasions a reviewer would try — violations moved into
`initContainers`/`ephemeralContainers`, a RoleBinding straight to `cluster-admin`
(`no-privileged-role-bindings`), images from outside the accounts ECR
(`restrict-registries`), wildcard `apiGroups`, and pseudo-digests (images must match
`@sha256:` + 64 hex, not merely contain the substring). Each attempt is a committed
failing fixture: `policy/kyverno/tests/resources/bypass-workload.yaml`.

## 4b — Terraform (fixed: `remediate/terraform/main-fixed.tf`)

| # | Defect | Exploitability here | Fix | Prevented by (rego rule) |
|---|--------|--------------------|-----|--------------------------|
| 1 | `publicly_accessible = true` **+** SG `0.0.0.0/0:5432` | The entire customer PII set is one leaked/guessed password from the internet — no foothold required. The single worst defect in the submission. | Private subnets; SG ingress **only** from the API pod SG, no CIDRs | `deny_rds_public`, `deny_sg_open_ingress` |
| 2 | `password = var.db_password` | Lands in state and plan output; with 40 committers it also ends up in tfvars/git (T3). | `manage_master_user_password` (Secrets Manager + CMK), non-default username | `deny_rds_password_in_config` |
| 3 | `storage_encrypted = false` | Needs AWS-side access (snapshot copy/share) to exploit, so ranks below the internet-facing pair — but it is unfixable in place later and fails every examiner. | CMK encryption | `deny_rds_unencrypted` |
| 4 | `backup_retention_period = 0` + `skip_final_snapshot` | Not attacker-"exploitable" directly; it converts *any* incident (ransom, fat-fingered delete) into permanent loss of a bank's ledgered data. | 30-day PITR, final snapshot, deletion protection | `deny_rds_no_backups` |
| 5 | CloudTrail: single-region, no validation, no global events | Post-compromise evasion: act in another region or against IAM and leave no record; unvalidated logs are deniable in front of a regulator. | Multi-region, validation, global events, KMS, org trail | `deny_cloudtrail_weak` |

Two notes on the fixed HCL beyond the defect table. First, it carries what `apply`
would actually require rather than silently assuming it: the CloudTrail bucket policy
(delivery fails without it), CMK key policies (CloudTrail encryption context on the
audit key; `kms:ViaService`-scoped use on the data key), Object Lock in COMPLIANCE mode
(7y) on the trail bucket, `rds.force_ssl = 1`, and `allocated_storage`. Second, the
rego rules deny the evasions of themselves: inline and `dynamic` SG blocks,
`aws_vpc_security_group_ingress_rule`, IPv6 ranges, sub-/8 CIDR pairs, Aurora
(`aws_rds_cluster*`), and variable-indirected values all fail closed — each encoded as
a test in `policy/rego/terraform_test.rego`.

## 4c — Pod identity IAM (rewrite: `iam/pod-identity-policy.json`)

The original is `NotAction: [two IAM deletes]` over `Resource: *` — i.e. **near-admin**:
it allows `iam:CreateAccessKey` / `AttachRolePolicy` (instant, quiet account takeover),
reading every secret in the account, and destroying most infrastructure; the second
statement re-grants secrets/KMS on `*` redundantly.

**One line, as asked:** my version denies all IAM and infrastructure mutation, every
secret except the service's own `prod/accounts-api/db-*`, KMS decrypt outside
Secrets Manager, and any read-back or deletion of audit records — the service can read
its one credential, consume one named stream, and append (never read) audit data.
