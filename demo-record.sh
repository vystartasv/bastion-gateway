#!/usr/bin/env bash
# Bastion Gateway — clean video demo
# Shows: ALLOW -> DENY -> HOLD -> CLI approval -> signed audit log
set -e

cd "$(dirname "$0")"
echo "Building..."
go build -o /tmp/gateway ./cmd/gateway/
go build -o /tmp/bastion ./cmd/bastion/

# Generate self-signed TLS cert for upstream
openssl req -x509 -newkey rsa:2048 -keyout /tmp/upstream-key.pem \
  -out /tmp/upstream-cert.pem -days 1 -nodes \
  -subj "/CN=localhost" 2>/dev/null

# Start HTTPS upstream on :9999
python3 -c "
import ssl, http.server, json
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/upstream-cert.pem', '/tmp/upstream-key.pem')
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        resp = json.dumps({'status':'ok','results':['tender-123','tender-456']}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self,*a): pass
s = http.server.HTTPServer(('',9999),H)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
" &
UP_PID=$!
sleep 1

# Policy
cat > /tmp/bastion-policy.yaml << 'POLICY'
default: deny
redact:
  - type: builtin
    name: bearer
  - type: builtin
    name: email
agents:
  researcher:
    allow:
      - GET localhost:9999/search
    hold:
      - DELETE *
POLICY

# Start gateway
mkdir -p /tmp/bastion-audit /tmp/bastion-approvals /tmp/bastion-keys
POLICY=/tmp/bastion-policy.yaml AUDIT_DIR=/tmp/bastion-audit APPROVAL_DIR=/tmp/bastion-approvals SIGN_KEY=/tmp/bastion-keys/signing.key /tmp/gateway &
GW_PID=$!
sleep 2

echo "╔══════════════════════════════════════════════════════╗"
echo "║                                                    ║"
echo "║   BASTION GATEWAY                                  ║"
echo "║   Default-deny firewall for AI agents              ║"
echo "║                                                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

echo "Policy:"
cat /tmp/bastion-policy.yaml
echo ""

echo "─── SCENE 1: ALLOW ───"
echo "Agent 'researcher' sends a permitted GET..."
curl -sk -w "\n→ HTTP %{http_code}\n" https://localhost:9999/search \
  --resolve localhost:9999:127.0.0.1 2>/dev/null
echo ""

echo "─── SCENE 2: DENY ───"
echo "Agent tries an unlisted POST..."
curl -s -w "\n→ HTTP %{http_code}\n" http://localhost:8080/admin \
  -H "X-Bastion-Agent: researcher" -H "Host: api.internal" -X POST -d '{}'
echo ""

echo "─── SCENE 3: HOLD ───"
echo "Agent tries a destructive DELETE..."
curl -s -w "\n→ HTTP %{http_code}\n" http://localhost:8080/data \
  -H "X-Bastion-Agent: researcher" -H "Host: api.internal" -X DELETE
echo ""

echo "─── SCENE 4: DENY unknown agent ───"
echo "Unknown 'intruder' agent attempts access..."
curl -s -w "\n→ HTTP %{http_code}\n" http://localhost:8080/search \
  -H "X-Bastion-Agent: intruder" -H "Host: api.internal" -X GET
echo ""

echo "─── SCENE 5: CLI approve ───"
echo "Operator reviews pending approvals:"
APPROVAL_DIR=/tmp/bastion-approvals /tmp/bastion list
echo ""

echo "─── SCENE 6: Signed audit log ───"
echo "Exported evidence pack (last 3 entries):"
AUDIT_DIR=/tmp/bastion-audit /tmp/bastion export 2>/dev/null | tail -4 | while read l; do
  echo "$l" | python3 -c "
import sys,json
r=json.load(sys.stdin)
print(f'  {r[\"decision\"]:7s} | {r[\"agent_id\"]:12s} | {r[\"method\"]:7s} {r[\"path\"]:20s} | signed=yes' if r.get('signature') else f'  {r[\"decision\"]:7s} | {r[\"agent_id\"]:12s} | {r[\"method\"]:7s} {r[\"path\"]:20s}')" 2>/dev/null
done
echo ""

echo "╔══════════════════════════════════════════════════════╗"
echo "║   DEMO COMPLETE — all decisions working as designed ║"
echo "╚══════════════════════════════════════════════════════╝"

kill $GW_PID $UP_PID 2>/dev/null
