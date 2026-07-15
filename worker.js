// Bastion Gateway landing page — served via Cloudflare Worker
// Replaces the old 410 nginx config

const HTML = `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bastion Gateway — default-deny firewall for AI agents</title>
<meta name="description" content="A firewall your agents route through. Allows what you permit, blocks what you don't, signs a record of everything. Apache-2.0, self-host free.">
<link rel="canonical" href="https://bastiongateway.com/">
<meta property="og:title" content="Bastion Gateway — default-deny for AI agents">
<meta property="og:description" content="A firewall your agents route through. Allows what you permit, blocks what you don't, signs a record of everything.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://bastiongateway.com/">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root { --ground: #0d2438; --ground-light: #e9f0f5; --line: #6fa8c7; --ink: #eef4f8; --ink-dark: #0d2438; --allowed: #3fae7a; --denied: #d8524d; --held: #e0a53a; --radius: 6px; --max: 960px; --body: Inter, system-ui, sans-serif; --mono: "JetBrains Mono", ui-monospace, monospace; }
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--ground);color:var(--ink);font-family:var(--body);font-size:16px;line-height:1.6}
.wrap{max-width:var(--max);margin:0 auto;padding:0 24px}
a{color:var(--line)}
a:hover{color:#fff}
:focus-visible{outline:2px solid var(--allowed);outline-offset:2px}
pre{font-family:var(--mono);font-size:13px;line-height:1.6;background:rgba(255,255,255,0.06);padding:18px;border-radius:var(--radius);overflow-x:auto;border:1px solid rgba(111,168,199,0.2)}
.btn{display:inline-block;padding:12px 22px;border-radius:var(--radius);font-size:15px;font-weight:600;text-decoration:none;border:1px solid transparent}
.btn-primary{background:var(--ink);color:var(--ground)}
.btn-primary:hover{background:var(--allowed);color:#fff}
.btn-secondary{border-color:var(--line);color:var(--ink)}
header{background:rgba(13,36,56,0.95);backdrop-filter:blur(8px);border-bottom:1px solid rgba(111,168,199,0.2);position:sticky;top:0;z-index:10}
.nav{display:flex;align-items:center;justify-content:space-between;height:60px}
.brand{font-weight:600;text-decoration:none;color:var(--ink);font-size:17px}
.brand span{color:var(--line)}
.nav ul{display:flex;gap:20px;font-size:14px;list-style:none}
.nav a:not(.brand){text-decoration:none;color:rgba(238,244,248,0.7)}
.bg-grid{background-image:linear-gradient(rgba(111,168,199,0.08) 1px, transparent 1px),linear-gradient(90deg, rgba(111,168,199,0.08) 1px, transparent 1px);background-size:40px 40px}
.hero{padding:80px 0 64px;border-bottom:1px solid rgba(111,168,199,0.15)}
.hero .wrap{display:grid;grid-template-columns:1fr 1fr;gap:48px;align-items:center}
@media(max-width:800px){.hero .wrap{grid-template-columns:1fr}}
.hero h1{font-size:clamp(30px,4.5vw,46px);font-weight:600;line-height:1.08;letter-spacing:-.01em;margin-bottom:14px}
.hero .sub{font-size:17px;color:rgba(238,244,248,0.7);max-width:44ch;margin-bottom:24px}
.cta-row{display:flex;flex-wrap:wrap;gap:12px;align-items:center}
.stamp{font-family:var(--mono);font-size:11px;letter-spacing:.08em;text-transform:uppercase;border-radius:3px;padding:3px 8px;display:inline-block;transform:rotate(-2deg)}
.stamp-allowed{color:var(--allowed);border:1.5px solid var(--allowed)}
.stamp-denied{color:var(--denied);border:1.5px solid var(--denied)}
.stamp-held{color:var(--held);border:1.5px solid var(--held)}
section{padding:64px 0;border-bottom:1px solid rgba(111,168,199,0.12)}
.section-label{font-family:var(--mono);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--line);margin-bottom:10px}
h2{font-size:clamp(22px,3vw,30px);font-weight:600;margin-bottom:8px}
.lede{color:rgba(238,244,248,0.65);max-width:60ch;margin-bottom:32px;font-size:15px}
.cap-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
@media(max-width:640px){.cap-grid{grid-template-columns:1fr}}
.cap{background:rgba(255,255,255,0.04);border:1px solid rgba(111,168,199,0.15);border-radius:8px;padding:22px}
.cap h3{font-size:16px;font-weight:600;margin-bottom:4px;display:flex;align-items:center;gap:10px}
.cap p{font-size:14px;color:rgba(238,244,248,0.6)}
.problem h2{font-size:clamp(26px,3.6vw,36px);max-width:16ch}
.problem .lines p{font-size:clamp(17px,2.2vw,22px);color:rgba(238,244,248,0.85);font-weight:500;margin:16px 0}
.problem .lines p:last-child{color:var(--denied)}
.qs-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:640px){.qs-grid{grid-template-columns:1fr}}
.qs-box{border:1px solid rgba(111,168,199,0.15);border-radius:8px;overflow:hidden}
.qs-box pre{border:0;border-radius:0;background:rgba(0,0,0,0.25)}
.qs-box .label{font-family:var(--mono);font-size:11px;padding:8px 14px;background:rgba(111,168,199,0.08);color:var(--line)}
.waitlist-box{background:rgba(255,255,255,0.04);border:1px solid rgba(111,168,199,0.15);border-radius:8px;padding:24px}
.waitlist-box input{background:rgba(0,0,0,0.3);border:1px solid rgba(111,168,199,0.25);border-radius:var(--radius);padding:12px 14px;font-size:15px;color:var(--ink);font-family:var(--body);width:280px;max-width:100%}
footer{padding:32px 0;font-size:13px;color:rgba(238,244,248,0.4)}
footer .wrap{display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between}
footer a{color:rgba(238,244,248,0.5)}
</style>
</head>
<body class="bg-grid">
<header><div class="wrap nav"><a class="brand" href="/">Bastion <span>Gateway</span></a><nav aria-label="Main"><ul><li><a href="#capabilities">Capabilities</a></li><li><a href="#quickstart">Quickstart</a></li><li><a href="https://github.com/vystartasv/bastion-gateway">GitHub</a></li></ul></nav></div></header>
<main>
<div class="hero"><div class="wrap"><div><p class="section-label">Default-deny for AI agents</p><h1>Default-deny for AI agents.</h1><p class="sub">A firewall your agents route through. It allows what you permit, blocks what you do not, and signs a record of everything it saw.</p><div class="cta-row"><a class="btn btn-primary" href="https://github.com/vystartasv/bastion-gateway">Get started</a></div><p style="margin-top:16px;font-size:13px;color:rgba(238,244,248,0.5)">Self-host free &middot; Apache-2.0 &middot; Runs on your infra, talks to nothing but your policy.</p></div><div><svg viewBox="0 0 400 340" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:400px"><path d="M200 10 L230 60 L290 50 L310 100 L370 110 L350 160 L380 200 L340 230 L330 280 L270 270 L240 310 L200 300 L160 310 L130 270 L70 280 L60 230 L20 200 L50 160 L30 110 L90 100 L110 50 L170 60 Z" stroke="#6fa8c7" stroke-width="1.5" fill="rgba(111,168,199,0.06)"/><rect x="175" y="130" width="50" height="60" rx="4" stroke="#6fa8c7" stroke-width="1.5" fill="rgba(63,174,122,0.1)"/><text x="200" y="167" text-anchor="middle" fill="#6fa8c7" font-family="monospace" font-size="8">GATEWAY</text><path d="M90 100 L120 115" stroke="#eef4f8" stroke-width="1.2" opacity="0.5"/><path d="M30 150 L70 150" stroke="#eef4f8" stroke-width="1.2" opacity="0.5"/><path d="M50 200 L80 185" stroke="#eef4f8" stroke-width="1.2" opacity="0.5"/><path d="M90 240 L120 225" stroke="#d8524d" stroke-width="1.5" opacity="0.8"/><text x="100" y="245" fill="#d8524d" font-family="monospace" font-size="7" transform="rotate(-2 100 245)">DENIED</text><path d="M5 5 L30 5 M5 5 L5 30" stroke="#6fa8c7" stroke-width="1" opacity="0.4"/><path d="M395 5 L370 5 M395 5 L395 30" stroke="#6fa8c7" stroke-width="1" opacity="0.4"/><path d="M5 335 L30 335 M5 335 L5 310" stroke="#6fa8c7" stroke-width="1" opacity="0.4"/><path d="M395 335 L370 335 M395 335 L395 310" stroke="#6fa8c7" stroke-width="1" opacity="0.4"/></svg></div></div></div>
<section class="problem"><div class="wrap"><h2>Your agents are already in production.</h2><div class="lines"><p>They can delete, spend, email, and leak — at machine speed, without asking.</p><p>Nothing is standing in front of them.</p></div></div></section>
<section id="capabilities"><div class="wrap"><p class="section-label">What it does</p><h2>Seven capabilities. One wall with a gate.</h2><p class="lede">Every capability ships today. No promises, no roadmap vapour.</p><div class="cap-grid"><div class="cap"><h3><span class="stamp stamp-allowed">ALLOWED</span> Allowlist</h3><p>Name the tools, domains, and endpoints each agent may touch. Everything else is denied by default.</p></div><div class="cap"><h3><span class="stamp stamp-denied">DENIED</span> Redaction</h3><p>Secrets and personal data are stripped from outbound calls before they leave your network.</p></div><div class="cap"><h3><span class="stamp stamp-held">HELD</span> Risk gate</h3><p>Destructive actions — deletes, spend, sends — don't just run. They stop and wait for a human to approve or reject.</p></div><div class="cap"><h3><span class="stamp stamp-allowed">ALLOWED</span> Signed audit log</h3><p>Every call becomes a signed, tamper-evident record — exportable as compliance evidence, not just a log file.</p></div><div class="cap"><h3><span class="stamp stamp-allowed">ALLOWED</span> Decision records</h3><p>Structured, versioned evidence payloads per EU AI Act Art 12–14/26. Identity, event context, decision content, reason, references, and integrity in every record.</p></div><div class="cap"><h3><span class="stamp stamp-allowed">ALLOWED</span> Hash chain</h3><p>Records are SHA-256 chained and Ed25519 signed. Tamper with one and the chain breaks — proven by automated verification, not policy.</p></div><div class="cap"><h3><span class="stamp stamp-allowed">ALLOWED</span> Offline verifier</h3><p>A standalone CLI (bastion-verify) validates every record, chain, and signature from an exported bundle. No production access, no network required.</p></div></div></div></section>
<section id="quickstart"><div class="wrap"><p class="section-label">Quickstart</p><h2>Point your agent at the gateway. Change one line.</h2><div class="qs-grid"><div class="qs-box"><div class="label">Docker</div><pre>docker run -p 8080:8080 -v ./policy.yaml:/policy.yaml:ro ghcr.io/vystartasv/bastion-gateway</pre></div><div class="qs-box"><div class="label">policy.yaml</div><pre>default: deny\nagents:\n  researcher:\n    allow:\n      - GET api.internal/*\n    hold:\n      - POST api.internal/orders/*\n      - DELETE *</pre></div></div></div></section>
<section><div class="wrap"><p class="section-label">Open source</p><h2>Read every line. Run it yourself.</h2><p class="lede">Apache-2.0. The whole gateway is on GitHub. No outbound calls except the traffic you send it.</p><div class="cta-row"><a class="btn btn-primary" href="https://github.com/vystartasv/bastion-gateway">View on GitHub</a></div></div></section>
</main>
<footer><div class="wrap"><span>Bastion Gateway &middot; Apache-2.0</span><span><a href="https://github.com/vystartasv/bastion-gateway">GitHub</a> &middot; <a href="https://workswithagents.com">Works With Agents</a> &middot; <a href="hello@bastiongateway.com">hello@bastiongateway.com</a></span></div></footer>
</body>
</html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Handle waitlist API
    if (url.pathname === '/api/waitlist' && request.method === 'POST') {
      // Store waitlist signups in KV
      const body = await request.json();
      if (!body.email || !body.email.includes('@')) {
        return new Response(JSON.stringify({ error: 'valid email required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Serve landing page for all routes
    return new Response(HTML, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      },
    });
  },
};
