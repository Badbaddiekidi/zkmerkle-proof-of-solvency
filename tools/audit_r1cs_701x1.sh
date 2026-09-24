cd ~/zkverify-1.2.1/zkmerkle-original-history && \
mkdir -p tools && \
nano tools/binance_r1cs_gate.sh
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

###############################################################################
# zkmerkle / zkverify
#
# Secure Binance credential gate + R1CS 701x1 audit launcher
#
# SECURITY MODEL
#   - Credentials are LOCAL ONLY.
#   - Nothing secret is stored in Git.
#   - Nothing secret is printed.
#   - No trading.
#   - No withdrawals.
#   - No transfers.
#   - Binance request is READ-ONLY.
#
# Required environment:
#   BINANCE_API_KEY
#   BINANCE_SECRET_KEY
#
# Optional local RSA key:
#   BINANCE_PRIVATE_KEY
#
###############################################################################

ROOT="$HOME/zkverify-1.2.1/zkmerkle-original-history"
AUDIT_DIR="$ROOT/.audit_tmp"

BINANCE_API="https://api.binance.com"
BINANCE_PERMISSION_ENDPOINT="/sapi/v1/account/apiRestrictions"

AUDIT_SOURCE="$AUDIT_DIR/r1cs701.go"
AUDIT_BIN="$AUDIT_DIR/r1cs701x1"
AUDIT_LOG="$AUDIT_DIR/r1cs701x1.final.log"

PEM_DEFAULT="$HOME/.config/zkmerkle/binance-private.pem"

GOMEMLIMIT="${GOMEMLIMIT:-5GiB}"
GOGC="${GOGC:-50}"
GOMAXPROCS="${GOMAXPROCS:-4}"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    unset BINANCE_API_KEY
    unset BINANCE_SECRET_KEY
    unset BINANCE_PRIVATE_KEY
}

trap cleanup EXIT

###############################################################################
# Environment
###############################################################################

cd "$ROOT" || die "repository not found"

mkdir -p "$AUDIT_DIR"

if [ -z "${BINANCE_API_KEY:-}" ]; then
    die "BINANCE_API_KEY is not loaded"
fi

if [ -z "${BINANCE_SECRET_KEY:-}" ]; then
    die "BINANCE_SECRET_KEY is not loaded"
fi

BINANCE_PRIVATE_KEY="${BINANCE_PRIVATE_KEY:-$PEM_DEFAULT}"

if [ ! -f "$BINANCE_PRIVATE_KEY" ]; then
    die "RSA private key not found"
fi

###############################################################################
# Secret hygiene
###############################################################################

case "$BINANCE_API_KEY" in
    *$'\n'*|*$'\r'*|*" "*)
        die "API key contains invalid whitespace"
        ;;
esac

case "$BINANCE_SECRET_KEY" in
    *$'\n'*|*$'\r'*)
        die "secret key contains invalid newline"
        ;;
esac

PEM_MODE="$(stat -c '%a' "$BINANCE_PRIVATE_KEY" 2>/dev/null || true)"

if [ "$PEM_MODE" != "600" ]; then
    die "RSA private key permissions must be 600"
fi

openssl pkey \
    -in "$BINANCE_PRIVATE_KEY" \
    -noout \
    >/dev/null 2>&1 \
    || die "RSA private key cannot be parsed"

###############################################################################
# Tool requirements
###############################################################################

command -v curl >/dev/null 2>&1 \
    || die "curl is required"

command -v openssl >/dev/null 2>&1 \
    || die "openssl is required"

command -v go >/dev/null 2>&1 \
    || die "go is required"

###############################################################################
# Binance HMAC signature
###############################################################################

timestamp="$(date +%s000)"
recv_window="5000"

query="timestamp=${timestamp}&recvWindow=${recv_window}"

signature="$(
    printf '%s' "$query" |
    openssl dgst -sha256 \
        -hmac "$BINANCE_SECRET_KEY" |
    awk '{print $2}'
)"

[ -n "$signature" ] \
    || die "failed to generate HMAC signature"

###############################################################################
# READ-ONLY Binance authentication check
#
# GET /sapi/v1/account/apiRestrictions
#
# This endpoint requires USER_DATA permission and a signed request.
###############################################################################

printf '%s\n' '============================================================'
printf '%s\n' ' BINANCE AUTHENTICATION CHECK'
printf '%s\n' '============================================================'
printf '%s\n' 'Mode: READ-ONLY'
printf '%s\n' 'Operation: API permission inspection'
printf '%s\n' 'Secrets: hidden'
printf '%s\n' '------------------------------------------------------------'

response="$(
    curl --silent \
         --show-error \
         --fail-with-body \
         --get \
         --url "${BINANCE_API}${BINANCE_PERMISSION_ENDPOINT}" \
         --header "X-MBX-APIKEY: ${BINANCE_API_KEY}" \
         --data-urlencode "timestamp=${timestamp}" \
         --data-urlencode "recvWindow=${recv_window}" \
         --data-urlencode "signature=${signature}"
)" || {
    printf '%s\n' 'BINANCE AUTH: FAILED'
    exit 10
}

###############################################################################
# Never print the raw response.
#
# We only inspect expected boolean permission fields.
###############################################################################

if printf '%s' "$response" | grep -q '"enableReading":true'; then
    printf '%s\n' 'API reading permission: ENABLED'
else
    printf '%s\n' 'API reading permission: NOT CONFIRMED'
fi

if printf '%s' "$response" | grep -q '"enableWithdrawals":true'; then
    printf '%s\n' 'WARNING: withdrawals permission is ENABLED'
else
    printf '%s\n' 'withdrawals permission: disabled/not enabled'
fi

if printf '%s' "$response" | grep -q '"enableSpotAndMarginTrading":true'; then
    printf '%s\n' 'WARNING: spot/margin trading permission is ENABLED'
else
    printf '%s\n' 'spot/margin trading permission: disabled/not enabled'
fi

printf '%s\n' 'BINANCE AUTH: SUCCESS'
printf '%s\n' '============================================================'

###############################################################################
# Circuit source verification
###############################################################################

[ -f "$AUDIT_SOURCE" ] \
    || die "missing audit source: $AUDIT_SOURCE"

if ! grep -q -E \
    'NewBatchCreateUserCircuit\(701|NewBatchCreateUserCircuit' \
    "$AUDIT_SOURCE"; then
    die "audit source does not contain expected circuit constructor"
fi

if ! grep -q -E \
    'frontend\.Compile' \
    "$AUDIT_SOURCE"; then
    die "audit source does not contain frontend.Compile"
fi

###############################################################################
# Constants
###############################################################################

grep -q -E \
    '^[[:space:]]*AssetCounts[[:space:]]*=[[:space:]]*701([[:space:]]|$)' \
    src/utils/constants.go \
    || die "AssetCounts is not 701"

grep -q -E \
    '^[[:space:]]*TierCount[[:space:]]*=[[:space:]]*12([[:space:]]|$)' \
    src/utils/constants.go \
    || die "TierCount is not 12"

###############################################################################
# Build
###############################################################################

if [ ! -x "$AUDIT_BIN" ]; then

    printf '%s\n' 'Building R1CS audit binary...'

    GOMAXPROCS="$GOMAXPROCS" \
    go build \
        -trimpath \
        -ldflags='-s -w' \
        -o "$AUDIT_BIN" \
        "$AUDIT_SOURCE" \
        || die "audit binary build failed"

    chmod 700 "$AUDIT_BIN"
fi

###############################################################################
# Record non-secret metadata
###############################################################################

META="$AUDIT_DIR/r1cs701x1.meta"

{
    printf 'timestamp='
    date -Iseconds

    printf 'assets=701\n'
    printf 'batches=1\n'
    printf 'gomemlimit=%s\n' "$GOMEMLIMIT"
    printf 'gogc=%s\n' "$GOGC"
    printf 'gomaxprocs=%s\n' "$GOMAXPROCS"

    printf 'audit_source_sha256='
    sha256sum "$AUDIT_SOURCE" | awk '{print $1}'

    printf 'audit_binary_sha256='
    sha256sum "$AUDIT_BIN" | awk '{print $1}'

    printf 'circuit_sha256='
    sha256sum circuit/batch_create_user_circuit.go | awk '{print $1}'

    printf 'constants_sha256='
    sha256sum src/utils/constants.go | awk '{print $1}'
} > "$META"

###############################################################################
# R1CS execution
###############################################################################

printf '%s\n' '============================================================'
printf '%s\n' ' R1CS 701×1'
printf '%s\n' '============================================================'

rm -f "$AUDIT_LOG"

START="$(date +%s)"

set +e

if command -v .timeout >/dev/null 2>&1; then

    GOMAXPROCS="$GOMAXPROCS" \
    GOMEMLIMIT="$GOMEMLIMIT" \
    GOGC="$GOGC" \
    GODEBUG="gctrace=1" \
    .timeout 900 \
    "$AUDIT_BIN" \
    2>&1 |
    tee "$AUDIT_LOG"

    RC=${PIPESTATUS[0]}

elif command -v timeout >/dev/null 2>&1; then

    GOMAXPROCS="$GOMAXPROCS" \
    GOMEMLIMIT="$GOMEMLIMIT" \
    GOGC="$GOGC" \
    GODEBUG="gctrace=1" \
    timeout 900 \
    "$AUDIT_BIN" \
    2>&1 |
    tee "$AUDIT_LOG"

    RC=${PIPESTATUS[0]}

else

    GOMAXPROCS="$GOMAXPROCS" \
    GOMEMLIMIT="$GOMEMLIMIT" \
    GOGC="$GOGC" \
    GODEBUG="gctrace=1" \
    "$AUDIT_BIN" \
    2>&1 |
    tee "$AUDIT_LOG"

    RC=${PIPESTATUS[0]}

fi

set -e

END="$(date +%s)"
ELAPSED=$((END - START))

###############################################################################
# Result
###############################################################################

printf '%s\n' '============================================================'
printf 'exit_code=%s\n' "$RC"
printf 'elapsed_seconds=%s\n' "$ELAPSED"

if grep -q 'nbSecret=88361' "$AUDIT_LOG"; then
    printf '%s\n' 'R1CS 701×1: CONFIRMED'
    printf '%s\n' 'nbSecret=88361'
else
    printf '%s\n' 'R1CS 701×1: NO CONFIRMADO'
fi

printf '%s\n' '============================================================'

exit "$RC"
