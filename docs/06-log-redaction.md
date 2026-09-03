# Section 6 — Log redaction: what is redacted, where, and what still leaks

In scope in request context: name, email, phone, IBAN, balance, last-4 of card,
account identifiers, KYC payloads.

## What is redacted, at which layer

**Layer 1 — application logging middleware (primary, allowlist).** Structured JSON
logging where the serializer emits an **allowlist** of known-safe fields (request id,
route *template*, status, latency, hashed customer id) and drops everything else.
Allowlist, not denylist: a denylist fails open on every new field; an allowlist fails
closed. Request/response bodies are never logged. `Authorization`, cookies, and KYC
payloads are never serialized.

**Layer 2 — log pipeline scrubber (backstop).** Fluent Bit on the node runs regex
scrubbing before shipping to CloudWatch: IBAN pattern (`[A-Z]{2}\d{2}[A-Z0-9]{11,30}`),
PAN-like digit runs (13–19 digits, Luhn-checked to cut false hits), email addresses.
This exists to catch what layer 1 misses — stack traces, third-party library log lines,
`panic` output — and its match count is exported as a metric: **every layer-2 hit is a
layer-1 bug** with a ticket.

**Layer 3 — access control on the sink.** CloudWatch log group KMS-encrypted,
90-day retention, read access to the service team only, access logged in CloudTrail.
Redaction failures should be a contained incident, not a second breach.

## What the redaction still leaks — honestly

- **Route/query identifiers:** even with route templates, a mis-instrumented handler
  logging the raw URL leaks account ids in paths and anything a client stuffs into
  query strings. Mitigated, not eliminated.
- **Third-party error passthrough:** the KYC provider's error bodies can echo the data
  we sent (name, DoB). Layer 1 drops known shapes; unknown shapes reach layer 2, whose
  regexes don't know what a name looks like. **Names and phone numbers in free text
  are effectively not redactable by pattern** — that's a data-minimisation problem
  (send the provider less), not a logging problem.
- **Metadata:** timing, response sizes, per-customer request frequency survive
  redaction and can identify or profile a customer in aggregate.
- **The hashed customer id** is a stable pseudonym — linkable across log lines by
  design; that linkability is itself personal data under most regimes.
- **Pre-middleware crash output** (before layer 1 initialises) goes raw to layer 2 and
  relies entirely on the regexes.

Claiming completeness here would be false. The honest posture: allowlist at source,
pattern backstop, treat every backstop hit as a defect, and keep the sink locked down
for the leaks that remain.
