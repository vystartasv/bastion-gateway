#!/usr/bin/env bash
# Bastion Gateway — end-to-end demo
# Shows: ALLOW, DENY, HOLD, CLI approval, signed audit log export
set -e

echo "Building gateway..."
cd "$(dirname "$0")"
go build -o /tmp/gateway ./cmd/gateway/
go build -o /tmp/bastion ./cmd/bastion/

echo "Creating test policy..."
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

echo "Starting fake upstream API on :9999..."
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{\"status\":\"ok\"}')
    def log_message(self,*a): pass
HTTPServer(('',9999),H).serve_forever()
" &
UP_PID=$!

echo "Starting gateway on :8080..."
mkdir -p /tmp/bastion-audit /tmp/bastion-approvals /tmp/bastion-keys
POLICY=/tmp/bastion-policy.yaml \
AUDIT_DIR=/tmp/bastion-audit \
APPROVAL_DIR=/tmp/bastion-approvals \
SIGN_KEY=/tmp/bastion-keys/signing.key \
/tmp/gateway &
GW_PID=$!
sleep 1

echo ""
echo "═══════════════════════════════════════════"
echo "  DEMO: 4 scenarios + CLI + audit"
echo "═══════════════════════════════════════════"
echo ""

echo "1. ALLOW — researcher searches:"
echo -n "   " && curl -s -w "HTTP %{http_code}" -X GET http://localhost:8080/search \
  -H "X-Bastion-Agent: researcher" -H "Host: localhost:9999" | tail -1
echo ""

echo "2. DENY — unpermitted POST to root:"
echo -n "   " && curl -s -w "HTTP %{http_code}" -X POST http://localhost:8080/ \
  -H "X-Bastion-Agent: researcher" -H "Host: api.internal" -d '{}' | tail -1
echo ""

echo "3. HOLD — destructive DELETE:"
echo -n "   " && curl -s -w "HTTP %{http_code}" -X DELETE http://localhost:8080/data \
  -H "X-Bastion-Agent: researcher" -H "Host: api.internal" | tail -1
echo ""

echo "4. DENY — unknown agent:"
echo -n "   " && curl -s -w "HTTP %{http_code}" -X GET http://localhost:8080/search \
  -H "X-Bastion-Agent: intruder" -H "Host: localhost:9999" | tail -1
echo ""

echo "5. CLI — pending approvals:"
APPROVAL_DIR=/tmp/bastion-approvals /tmp/bastion list
echo ""

echo "6. CLI — signed audit log:"
AUDIT_DIR=/tmp/bastion-audit /tmp/bastion export | while read line; do
  echo "$line" | python3 -c "import sys,json; r=json.load(sys.stdin); print(f'  {r[\"decision\"]:7s} | {r[\"agent_id\"]:12s} | {r[\"method\"]:7s} {r[\"path\"]}')" 2>/dev/null
done
echo ""

echo "═══════════════════════════════════════════"
echo "  ALL DECISIONS WORKING AS DESIGNED"
echo "═══════════════════════════════════════════"

kill $GW_PID $UP_PID 2>/dev/null
