# Section 5 — Admission and Runtime

## Admission: mode per policy, and what promotes it

Policies: `policy/kyverno/policies/`. Test proof: `test-output/kyverno-test.txt`
(34/34 — the in-production manifest rejected rule-by-rule, the fixed one clean, and a
bypass fixture of evasion attempts rejected too).

A cluster shared with ~12 teams is a rollout problem: every policy is a `ClusterPolicy`
with `validationFailureAction: Audit` cluster-wide and an **Enforce override for the
`accounts` namespace** — we eat our own enforcement on day one, nobody else's workloads
break, and PolicyReports accumulate evidence per namespace.

| Policy | accounts (day 1) | cluster (day 1) | Promotion to Enforce |
|---|---|---|---|
| disallow-hostpath | Enforce | Audit | Per-namespace, after 14 days with zero PolicyReport violations **and** the owning team's ack. Platform announces a date; the PolicyReport is the evidence a regulator and the team both see. |
| disallow-host-namespaces | Enforce | Audit | Same criteria. CNI/monitoring DaemonSets get a named-namespace exemption, not a policy hole. |
| require-run-as-nonroot | Enforce | Audit | Same criteria; longest expected tail (base images with root defaults). |
| restrict-rbac-wildcards | Enforce | Audit | Same; violations here get a direct conversation, not just a report. |
| require-image-digest | Enforce (accounts) | Audit | Requires the team to consume digests from their pipeline — promoted team-by-team as they adopt the build-release pattern. |
| disallow-secrets-from-env | Audit (everywhere) | Audit | Per-namespace after the team migrates to file mounts; 14 clean days. Covers envFrom *and* per-key secretKeyRef, init containers included — migrating between the two leak shapes doesn't clear the audit. |
| restrict-registries | Enforce (accounts only) | — (not applied) | Companion to signature verification: verifyImages only evaluates images matching its references, so the namespace also pins the registry itself. Other namespaces get their own allowlists as they onboard. |
| verify-image-signature | Enforce (accounts only) | — (not applied) | Scoped to accounts-api's image reference; other teams onboard when they sign. `failurePolicy: Fail` — an admission outage must not admit unsigned images. |

Promotion evidence, concretely: 14 consecutive days of zero violations in the
namespace's PolicyReport + a dated announcement + the team's ack in the tracking issue.
"Quiet report + informed owner" is the bar; a calendar date alone is not.

## Runtime detection

`runtime/falco-rules.yaml` — two rules written for this workload (single static
binary, read-only rootfs ⇒ any spawned process or foreign read of the mounted DB
credential is hostile). Payload, routing (Falcosidekick → SNS → PagerDuty), the
platform on-call ownership, and the 3-step runbook: `runtime/runbook.md`.

## Egress (T4/T2) — the layer argument

Config: `network/egress.yaml`. NetworkPolicy alone cannot express an FQDN whose IPs
rotate, and doing FQDN at the CNI (Cilium DNS-aware policy) couples a security control
to DNS-answer snooping — fine, but we don't get to choose the shared cluster's CNI.
So: **NetworkPolicy guarantees the pod reaches only DNS, RDS, the stream endpoint, and
a dedicated forward proxy; the proxy owns the FQDN decision** (Squid allowlist, exactly
one host, CONNECT/443 only, every decision logged). Defence in depth where each layer
does the thing it's actually good at.

**What it still fails to stop — honestly:**
1. Exfiltration *to the KYC provider itself*: the allowed pipe is still a pipe. The
   proxy logs volume, so anomalous throughput is detectable after the fact, not blocked.
2. DNS tunnelling through the permitted cluster resolver (CoreDNS forwards out). Rate
   or entropy limits on CoreDNS shrink but don't close this.
3. Anything before admission ran (init containers admitted before policy existed) —
   why promotion discipline matters.
4. A compromised proxy: it is in the TCB now; it runs in its own namespace under the
   same admission baseline.
