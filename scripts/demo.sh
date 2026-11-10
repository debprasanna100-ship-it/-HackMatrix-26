#!/usr/bin/env bash
# TrustLens demo — submit → investigate → commit on-chain → verify → correlate.
#
# Assumes the stack is running (see README "Quick start" or docker compose up):
#   backend on :8000 with chain features enabled
#
# Optional overrides:
#   TRUSTLENS_BASE_URL=http://127.0.0.1:8000 ./scripts/demo.sh
set -euo pipefail

BASE="${TRUSTLENS_BASE_URL:-http://127.0.0.1:8000}"
PY="${TRUSTLENS_PYTHON:-python}"

banner() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }
die()    { printf "\n\033[1;31mFAILED: %s\033[0m\n" "$1" >&2; exit 1; }

banner "0. Health"
curl -sf "$BASE/health" > /dev/null || die "backend unreachable at $BASE — is it running with chain features enabled?"
echo "backend OK: $BASE"

banner "1. Submit a suspicious URL"
REPORT=$(curl -sf -X POST "$BASE/api/v1/analyze/url" -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1.com.verify-account.xyz/login"}') || die "analyze failed"
RID=$($PY -c "import json,sys; print(json.load(sys.stdin)['report_id'])" <<< "$REPORT")
$PY - "$REPORT" << 'EOF'
import json, sys
r = json.loads(sys.argv[1])
print("report_id:      ", r["report_id"])
print("classification: ", r["classification"])
for f in r["findings"][:4]:
    print(f"  [{f['severity']:>6}] {f['id']}: {f['title']}")
print("coverage:       ", f"{r['coverage']['completed']}/{r['coverage']['attempted']}")
EOF

banner "2. Commit the report on-chain (ThreatRegistry)"
COMMIT=$(curl -sf -X POST "$BASE/api/v1/reports/$RID/commit") || die "commit failed — is the local chain running and TRUSTLENS_REGISTRY_ADDRESS (or deployment file) wired?"
$PY - "$COMMIT" << 'EOF'
import json, sys
c = json.loads(sys.argv[1])
print("tx hash:        ", c["tx_hash"])
print("contract:       ", c["contract_address"], "| block:", c["block_number"])
print("committed hash: ", c["report_hash"][:34] + "…")
EOF

banner "3. Independent verification (anyone, no submission needed)"
VERIFY=$(curl -sf "$BASE/api/v1/verify/$RID") || die "verify failed"
$PY - "$VERIFY" << 'EOF'
import json, sys
v = json.loads(sys.argv[1])
print("integrity match:", v["integrity_match"])
print("on-chain exists:", v["on_chain"]["exists"], "| status:", v["on_chain"].get("status"))
print("reporter:       ", v["on_chain"].get("reporter"))
EOF

banner "4. Correlation (rule-based)"
CORR=$(curl -sf "$BASE/api/v1/correlate/$RID")
$PY - "$CORR" << 'EOF'
import json, sys
c = json.loads(sys.argv[1])
print(c["summary"])
EOF

banner "5. Message analysis (phishing SMS)"
MSG=$(curl -sf -X POST "$BASE/api/v1/analyze/message" -H "Content-Type: application/json" \
  -d '{"message": "FINAL NOTICE: your bank account will be permanently disabled within 24 hours. Read aloud the one-time code we just sent."}') || die "message analyze failed"
$PY - "$MSG" << 'EOF'
import json, sys
r = json.loads(sys.argv[1])
print("classification: ", r["classification"])
print("tactics:        ", [t["tactic"] for t in r["extras"]["message"]["tactics"]])
print("findings:       ", [f["id"] for f in r["findings"]])
print("explanation by: ", r["explanation"]["generated_by"])
EOF

banner "DONE"
echo "Open the report in the UI:  http://localhost:5173/reports/$RID"
echo "Verify page (share the ID): http://localhost:5173/verify"
