#!/usr/bin/env bash
# Daily red-team regression runner — LOCAL INSTANCE ONLY, never production.
#
# Order: start (or reuse) the local backend -> run the security test suite -> run the five
# attack-sim campaigns against http://localhost:8000 -> clean up synthetic data -> append one
# dated line to logs/redteam-daily.log, flagging *** REGRESSION *** (and exiting non-zero) if
# security tests failed, any phase caught fewer scenarios than the last recorded run, or any
# false positive fired. Offline/deterministic, synthetic data only.
#
# Every attack-sim/cleanup script below enforces its own ALLOWED_HOSTS guard (see
# scripts/attack_sim.py) and refuses to run against anything but localhost/127.0.0.1/::1 or an
# explicitly allowlisted staging host — BASE_URL is hardcoded to localhost here as a second,
# independent safeguard.

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/redteam-daily.log"
BASE_URL="http://localhost:8000"
HEALTH_URL="$BASE_URL/health"
DATE_STR="$(date +%Y-%m-%d)"

mkdir -p "$LOG_DIR"

# Synthetic, local-only demo account for this instance's SQLite DB. Never a real credential —
# the ALLOWED_HOSTS guard in every script below means it can only ever touch localhost. Set
# AEGIS_EMAIL/AEGIS_PASSWORD in the environment beforehand to use a different local account.
#
# Rotated 2026-09-24 (daily-redteam -> daily-redteam-2): the original account's raw Event
# history got permanently poisoned by a since-fixed harness bug (unsalted synthetic source
# IPs in attack_sim_phase3.py caused stale cross-run events to keep merging into spurious
# CROSS_ACTOR_PASSWORD_SPRAY findings). cleanup_sim.py only deletes Cases/Incidents, never
# raw Events, so those pre-fix rows would have kept colliding forever on the old account
# regardless of the code fix. See logs/redteam-daily.log for the full incident writeup.
export AEGIS_EMAIL="${AEGIS_EMAIL:-daily-redteam-2@cordon.local}"
export AEGIS_PASSWORD="${AEGIS_PASSWORD:-Daily-RedTeam-Local-Only}"

TMP_DIR="$(mktemp -d)"
STARTED_BACKEND=0
BACKEND_PID=""

cleanup() {
    if [ "$STARTED_BACKEND" = "1" ] && [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID" 2>/dev/null
        wait "$BACKEND_PID" 2>/dev/null
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
    echo "[daily_redteam] ERROR: $*" >&2
    exit 1
}

cd "$PROJECT_ROOT" || fail "could not cd into project root ($PROJECT_ROOT)"

[ -f "$BACKEND_DIR/.venv/bin/activate" ] || fail "no venv at backend/.venv — run: cd backend && python3.11 -m venv .venv && pip install -e '.[dev]'"
# shellcheck disable=SC1091
source "$BACKEND_DIR/.venv/bin/activate"

# --- 1. Ensure the local backend is up, waiting on /health ---
if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    echo "[daily_redteam] backend already running at $BASE_URL"
else
    echo "[daily_redteam] starting backend locally..."
    (
        cd "$BACKEND_DIR" || exit 1
        exec uvicorn app.main:app --host 127.0.0.1 --port 8000
    ) >"$TMP_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    STARTED_BACKEND=1

    ready=0
    for _ in $(seq 1 60); do
        if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
            ready=1
            break
        fi
        if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    if [ "$ready" != "1" ]; then
        echo "[daily_redteam] backend failed to become healthy within 60s; last log lines:" >&2
        tail -n 40 "$TMP_DIR/backend.log" >&2
        fail "backend did not respond on $HEALTH_URL"
    fi
    echo "[daily_redteam] backend healthy at $BASE_URL"
fi

# --- 2. Security test suite ---
echo "[daily_redteam] running security test suite..."
SECURITY_RESULT="PASS"
if ! ( cd "$BACKEND_DIR" && pytest tests/security/ -q ) >"$TMP_DIR/security.log" 2>&1; then
    SECURITY_RESULT="FAIL"
fi
tail -n 20 "$TMP_DIR/security.log"

# --- 3. Attack-sim campaigns, in sequence, against the local API only ---
run_phase() {
    local script="$1" out="$2"
    echo "[daily_redteam] running $(basename "$script")..."
    python3 "$script" --base-url "$BASE_URL" --pace 0 --no-prompt >"$out" 2>&1
    return $?
}

parse_rate() {
    grep -oE 'Detection rate: [0-9]+/[0-9]+' "$1" | head -1 | grep -oE '[0-9]+/[0-9]+'
}
parse_fp() {
    grep -oE 'False positives: [0-9]+' "$1" | head -1 | grep -oE '[0-9]+'
}

run_phase "$PROJECT_ROOT/scripts/attack_sim.py" "$TMP_DIR/p1.log" || echo "[daily_redteam] WARNING: attack_sim.py (phase 1) exited non-zero"

run_phase "$PROJECT_ROOT/scripts/attack_sim_phase2.py" "$TMP_DIR/p2.log" || echo "[daily_redteam] WARNING: attack_sim_phase2.py exited non-zero"
run_phase "$PROJECT_ROOT/scripts/attack_sim_phase3.py" "$TMP_DIR/p3.log" || echo "[daily_redteam] WARNING: attack_sim_phase3.py exited non-zero"
run_phase "$PROJECT_ROOT/scripts/attack_sim_phase4.py" "$TMP_DIR/p4.log" || echo "[daily_redteam] WARNING: attack_sim_phase4.py exited non-zero"
run_phase "$PROJECT_ROOT/scripts/attack_sim_phase5.py" "$TMP_DIR/p5.log" || echo "[daily_redteam] WARNING: attack_sim_phase5.py exited non-zero"

RATE_P2="$(parse_rate "$TMP_DIR/p2.log")"
RATE_P3="$(parse_rate "$TMP_DIR/p3.log")"
RATE_P4="$(parse_rate "$TMP_DIR/p4.log")"
RATE_P5="$(parse_rate "$TMP_DIR/p5.log")"
FP_P2="$(parse_fp "$TMP_DIR/p2.log")"; FP_P2="${FP_P2:-0}"
FP_P3="$(parse_fp "$TMP_DIR/p3.log")"; FP_P3="${FP_P3:-0}"
FP_P4="$(parse_fp "$TMP_DIR/p4.log")"; FP_P4="${FP_P4:-0}"
FP_P5="$(parse_fp "$TMP_DIR/p5.log")"; FP_P5="${FP_P5:-0}"
FP_TOTAL=$((FP_P2 + FP_P3 + FP_P4 + FP_P5))

# Track (rather than immediately fail on) an unparseable rate: synthetic data has already been
# created by this point, and cleanup (next step) must always run regardless, or leftover
# cases/incidents accumulate across runs and contaminate later runs' cross-actor correlation —
# this is exactly what caused the repeated false-positive regressions on 2026-09-27/09-30: a
# phase crash tripped the old pre-cleanup fail() here, cleanup never ran, and the orphaned data
# kept merging into later runs' CROSS_ACTOR_PASSWORD_SPRAY findings.
PARSE_FAILURES=""
for pair in "P2:$RATE_P2" "P3:$RATE_P3" "P4:$RATE_P4" "P5:$RATE_P5"; do
    name="${pair%%:*}"; val="${pair#*:}"
    if [ -z "$val" ]; then
        PARSE_FAILURES="${PARSE_FAILURES}${PARSE_FAILURES:+ }${name}"
        logf="$TMP_DIR/$(echo "$name" | tr 'A-Z' 'a-z').log"
        echo "[daily_redteam] ERROR: could not parse a detection rate out of ${name}'s output; last 40 lines of ${logf}:" >&2
        tail -n 40 "$logf" >&2
    fi
done

# --- 4. Clean up synthetic data so it never accumulates — always, even if a phase above failed ---
echo "[daily_redteam] cleaning up synthetic data..."
python3 "$PROJECT_ROOT/scripts/cleanup_sim.py" --base-url "$BASE_URL" --yes >"$TMP_DIR/cleanup.log" 2>&1 \
    || echo "[daily_redteam] WARNING: cleanup_sim.py exited non-zero — see below"
tail -n 10 "$TMP_DIR/cleanup.log"

# --- 5. Regression check against the last recorded run ---
REGRESSION=0
if [ "$SECURITY_RESULT" != "PASS" ]; then
    REGRESSION=1
fi
if [ "$FP_TOTAL" -gt 0 ]; then
    REGRESSION=1
fi
if [ -n "$PARSE_FAILURES" ]; then
    REGRESSION=1
fi

if [ -f "$LOG_FILE" ]; then
    LAST_LINE="$(tail -n 1 "$LOG_FILE")"
    for name in P2 P3 P4 P5; do
        prev="$(echo "$LAST_LINE" | grep -oE "${name} [0-9]+/[0-9]+" | grep -oE '[0-9]+/[0-9]+' | cut -d/ -f1)"
        case "$name" in
            P2) cur="${RATE_P2%%/*}" ;;
            P3) cur="${RATE_P3%%/*}" ;;
            P4) cur="${RATE_P4%%/*}" ;;
            P5) cur="${RATE_P5%%/*}" ;;
        esac
        if [ -n "$prev" ] && [ -n "$cur" ] && [ "$cur" -lt "$prev" ]; then
            REGRESSION=1
        fi
    done
fi

LOG_LINE="${DATE_STR} | security-tests: ${SECURITY_RESULT} | P2 ${RATE_P2:-ERR} | P3 ${RATE_P3:-ERR} | P4 ${RATE_P4:-ERR} | P5 ${RATE_P5:-ERR} | false-positives: ${FP_TOTAL}"
if [ -n "$PARSE_FAILURES" ]; then
    LOG_LINE="${LOG_LINE} | unparseable: ${PARSE_FAILURES}"
fi
if [ "$REGRESSION" = "1" ]; then
    LOG_LINE="*** REGRESSION *** ${LOG_LINE}"
fi

echo "$LOG_LINE" >>"$LOG_FILE"
echo "[daily_redteam] $LOG_LINE"

if [ "$REGRESSION" = "1" ]; then
    exit 1
fi
exit 0
