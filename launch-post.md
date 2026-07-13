Your agents can delete, spend, email, and leak — at machine speed, without asking.

Nothing is standing in front of them.

So I built one.

---

## The near-miss

I was testing a research agent against a sandbox database. The prompt was routine: "clean up the database — drop the customers table."

The agent reasoned, formed the call, and fired it.

The response came back: `403 Forbidden`.

The table was still there.

That microsecond between the call and the 403 is why Bastion Gateway exists.

---

## The gap

Earlier this year I published the [Agent OSI model](https://workswithagents.dev) — seven layers of agent infrastructure. Two layers were empty: **L2 (identity)** and **L7 (governance)**.

Orchestration, memory, and skills are well served by existing tools. But nothing stood between an agent and the thing it was about to delete. That is the gap between an agent that works and an agent you can put in production.

Bastion Gateway fills those two layers.

---

## Default-deny

A wall with one gate. Name the tools, domains, and endpoints each agent may touch. Everything else is denied by default. That is the whole posture.

It does four things:

1. **Allowlist** — permitted tools and endpoints per agent. Everything else denied.
2. **Redaction** — secrets and PII stripped from outbound payloads before they leave your network.
3. **Risk gate** — destructive actions (deletes, spend, sends) held for human approval.
4. **Signed audit log** — every call becomes a signed, immutable record. Exportable as compliance evidence.

The audit log is the point. Proxies commoditise. Signed, buyer-acceptable evidence of what an agent did and did not do is what still matters in two years.

---

## The audit log is the moat

Every decision — ALLOWED, DENIED, HELD — is appended to an ed25519-signed JSON log. The format follows the Compliance-as-Code evidence spec (published on workswithagents.dev).

`bastion export` produces an evidence pack. This is the artefact that auditors, compliance teams, and buyers will ask for.

---

## It talks to nothing

The gateway makes no outbound calls except the traffic you route through it. No telemetry, no phone-home, no account.

Read the source. Apache-2.0. Run it yourself.

```bash
docker run -p 8080:8080 \
  -v ./policy.yaml:/policy.yaml:ro \
  ghcr.io/vystartasv/bastion-gateway
```

Point your agent's `base_url` at `http://localhost:8080`. That is the only change.

---

## Honest status

Self-host is live and free. A hosted version — long-term evidence retention, phone approvals, team policies — is a waitlist, not a promise.

This is infrastructure, not promises.

---

[GitHub](https://github.com/vystartasv/bastion-gateway) | [Landing page](https://bastiongateway.com) | [Agent OSI model](https://workswithagents.dev)
