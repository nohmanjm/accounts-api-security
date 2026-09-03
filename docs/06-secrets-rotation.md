# Section 6 — Secrets: delivery path and rotation

## Delivery path (T3): source of truth → running process

`AWS Secrets Manager (prod/accounts-api/db-app-user, CMK-encrypted)`
`→ External Secrets Operator (its own IRSA role, tag-scoped read)`
`→ K8s Secret accounts-api-db (etcd encrypted with KMS — EKS envelope encryption)`
`→ read-only tmpfs file mount at /var/secrets/db in the pod`

Manifests: `secrets/external-secrets.yaml`. Nothing plaintext in repo or committed
manifests; the K8s Secret object is *created by the controller*, never by a human or a
pipeline. File mount, not env (defect 4a#6): nothing in `/proc`, dumps, or child
processes, and the Falco credential-read rule gets a concrete file path to guard.
Both halves of the identity chain are committed: the app pod's policy
(`iam/pod-identity-policy.json`) and the ESO controller's tag- and path-scoped policy
(`iam/eso-policy.json`) — neither can read another team's credentials. In transit:
`rds.force_ssl = 1` in the DB parameter group, so a cleartext connection is refused
server-side regardless of client configuration.

**Production mapping:** Secrets Manager + IRSA exactly as committed. Local validation:
manifests dry-run against a kind cluster; no AWS applied, per the brief.

## Rotation

| Credential | Mechanism | Interval | Emergency target |
|---|---|---|---|
| DB app user (`db-app-user`) | Secrets Manager rotation lambda, **two-user alternation** (rotate the idle user, flip) — no connection outage | 30 days | **< 15 min** |
| RDS master | `manage_master_user_password` (RDS-managed) | 30 days (AWS-managed) | < 30 min |
| KYC API key | Provider portal (manual — honest: no API offered) | 90 days | < 60 min, gated on provider; documented, rehearsed |
| AWS access (pod + CI) | None stored anywhere — IRSA / OIDC issue short-lived STS tokens | 1h max session | Revoke: deny-all session policy, effective in minutes |
| Cosign key | Does not exist (keyless) | — | — |

**Rotation during an active incident** — the part that matters: the scheduled path is
irrelevant mid-incident; the emergency path is:

1. `aws secretsmanager rotate-secret --secret-id prod/accounts-api/db-app-user`
   — immediate out-of-cycle rotation (~1 min).
2. Annotate the ExternalSecret (`force-sync`) — ESO re-syncs now, not at the next 1h
   tick (~seconds).
3. The app re-reads `/var/secrets/db` on new connections; belt-and-braces
   `kubectl rollout restart` bounds it to pod startup time (~2 min).
4. **Kill the old credential's live sessions**: `pg_terminate_backend` for the old DB
   user — rotation without session termination leaves the attacker connected.

Rehearsed quarterly; the measured number goes in the incident template. **Target: every
credential this service holds rotated in < 15 minutes**, except the KYC key where the
provider is the bottleneck — that dependency is a named risk, accepted and written down,
with the compensating control that the KYC key authorises lookups only, no customer
data reads.

## Encryption — the one line, and what it actually addresses

Data at rest (RDS storage, its snapshots, Secrets Manager, EBS, the audit bucket) is
encrypted under **customer-managed KMS keys held in our management account, key policy
scoped to service roles, yearly-rotated, usage CloudTrail-logged**. What that addresses
*in this architecture*: a stolen/shared snapshot, a mis-scoped backup copy, decommissioned
media, and a cross-account IAM slip — i.e. AWS-side access-control failures. What it does
**not** address: a compromised app holding valid credentials reads plaintext regardless.
Encryption at rest here is a compliance-and-blast-radius control, not an app-compromise
control — priced accordingly.
