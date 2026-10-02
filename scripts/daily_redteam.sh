#!/usr/bin/env bash
# Daily red-team regression runner — LOCAL INSTANCE ONLY, never production.
#
# Order: start (or reuse) the local backend -> run the security test suite -> run the
# real-world commodity/criminal attack suite (scripts/attack_sim_realworld.py) against
# http://localhost:8000 -> append one dated line to logs/redteam-daily.log, flagging
# *** REGRESSION *** (and exiting non-zero) if security tests failed, the detection rate
# dropped versus the last recorded run, or any false positive fired (the suite's hard bar is
# ZERO false positives, not just a rate). Offline/deterministic, synthetic data only.
#
# No shared demo account and no cleanup step here (unlike the old phase1-5 runner this
# replaced): attack_sim_realworld.py creates its own brand-new, isolated account every run and
# never reuses one. That's a structural fix, not a convenience — the account-rotation history
# above this comment in earlier revisions of this file documents two real regressions
# (2026-09-27, 2026-09-30) caused by a shared account's leftover Events (append-only; see
# app/api/routes/events.py) getting "rediscovered" into spurious incidents once an old
# incident covering them was deleted by the since-removed cleanup step. An account this
# script never deletes anything from, and never revisits, cannot hit that path. See
# scripts/attack_sim_realworld.py's module docstring for the full isolation rationale and the
# accepted trade-off (one throwaway account per day, never cleaned up — harmless on a local
# dev SQLite instance).
#
# The nation-state/APT simulation (scripts/attack_sim_phase4.py) is intentionally NOT part of
# this daily run — see scripts/monthly_redteam_apt.sh for that "ceiling/honesty" test, which
# runs monthly and logs to its own file without gating this daily green.
#
# scripts/attack_sim_realworld.py enforces its own ALLOWED_HOSTS guard and refuses to run
# against anything but localhost/127.0.0.1/::1 or an explicitly allowlisted staging host —
# BASE_URL is hardcoded to localhost here as a second, independent safeguard.

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/redteam-daily.log"
BASE_URL="http://localhost:8000"
HEALTH_URL="$BASE_URL/health"
DATE_STR="$(date +%Y-%m-%d)"

mkdir -p "$LOG_DIR"

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

# --- 3. Real-world commodity/criminal attack suite (its own isolated account; no cleanup needed) ---
echo "[daily_redteam] running attack_sim_realworld.py..."
python3 "$PROJECT_ROOT/scripts/attack_sim_realworld.py" --base-url "$BASE_URL" --pace 0 --no-prompt \
    >"$TMP_DIR/realworld.log" 2>&1
REALWORLD_EXIT=$?
tail -n 25 "$TMP_DIR/realworld.log"

parse_rate() {
    grep -oE 'Detection rate: [0-9]+/[0-9]+' "$1" | head -1 | grep -oE '[0-9]+/[0-9]+'
}
parse_fp() {
    grep -oE 'False positives: [0-9]+' "$1" | head -1 | grep -oE '[0-9]+'
}

RATE="$(parse_rate "$TMP_DIR/realworld.log")"
FP="$(parse_fp "$TMP_DIR/realworld.log")"; FP="${FP:-0}"

if [ -z "$RATE" ]; then
    echo "[daily_redteam] ERROR: could not parse a detection rate out of attack_sim_realworld.py's output (exit=$REALWORLD_EXIT); full output:" >&2
    cat "$TMP_DIR/realworld.log" >&2
fi

# --- 4. Regression check against the last recorded run ---
REGRESSION=0
if [ "$SECURITY_RESULT" != "PASS" ]; then
    REGRESSION=1
fi
if [ "$FP" -gt 0 ]; then
    REGRESSION=1
fi
if [ -z "$RATE" ]; then
    REGRESSION=1
fi

if [ -n "$RATE" ] && [ -f "$LOG_FILE" ]; then
    LAST_LINE="$(tail -n 1 "$LOG_FILE")"
    PREV="$(echo "$LAST_LINE" | grep -oE "realworld [0-9]+/[0-9]+" | grep -oE '[0-9]+/[0-9]+' | cut -d/ -f1)"
    CUR="${RATE%%/*}"
    if [ -n "$PREV" ] && [ "$CUR" -lt "$PREV" ]; then
        REGRESSION=1
    fi
fi

LOG_LINE="${DATE_STR} | security-tests: ${SECURITY_RESULT} | realworld ${RATE:-ERR} | false-positives: ${FP}"
if [ "$REGRESSION" = "1" ]; then
    LOG_LINE="*** REGRESSION *** ${LOG_LINE}"
fi

echo "$LOG_LINE" >>"$LOG_FILE"
echo "[daily_redteam] $LOG_LINE"

if [ "$REGRESSION" = "1" ]; then
    exit 1
fi
exit 0
