# Decisions Log

## 2026-07-13 — Bastion Gateway v1 Build

### Architecture
- Language: Go (single static binary, scratch Docker image)
- No database: file-based approvals queue + JSONL audit log
- No outbound calls except proxied traffic

### Deviations from plan
- CI workflow: committed, SSH-pushed to GitHub. Uses go test + build.
- Landing page: built as static HTML with inline SVG. Waitlist POSTs to /api/waitlist.
- Demo: not yet recorded. Needs screen recording tool + running agent.
- DNS: bastiongateway.com still returns 410. Nginx config ready but not deployed.
- Theme: Fortress blueprint, deep blue #0d2438, line #6fa8c7. NOT paper-and-ink from WWA.

### Out of scope (logged, not built)
- Phone-push approvals (hosted-tier hook)
- Trust-score adapter (stub + docs only)
- Disclosure adapter (stub + docs only)
- Pricing page, hosted sign-up flow

### Repos
- github.com/vystartasv/bastion-gateway — public, Apache-2.0
- github.com/vystartasv/wwa-site — static site for workswithagents.com (frozen)

### Cross-links (pending deploy)
- bastiongateway.com footer → workswithagents.com, workswithagents.dev
- workswithagents.dev blog → link to the gateway as L2+L7
- Repo README → links back to bastiongateway.com
