#!/usr/bin/env bash
# Monthly nation-state/APT "ceiling / honesty" test — LOCAL INSTANCE ONLY, never production.
#
# scripts/attack_sim_phase4.py simulates elite-tier, nation-state-grade tradecraft
# deliberately engineered to slip underneath today's detection thresholds — most of its
# scenarios are EXPECTED to be missed; that's the honest ceiling of what today's defenses
# catch, not a regression. It does NOT gate this project's daily green (see
# scripts/daily_redteam.sh, which runs the real-world commodity/criminal suite instead) —
# this script only ever logs its result to logs/redteam-monthly-apt.log and always exits 0
# (except on a genuine setup/connectivity failure), regardless of how many scenarios it
# misses. Run monthly (see com.cordon.monthly-redteam-apt.plist) since nation-state-grade
# tradecraft coverage changes slowly — there's no value in re-running this daily.
#
# Isolation: like the daily runner, this uses a brand-new, isolated account every run
# (AEGIS_EMAIL/AEGIS_PASSWORD below) instead of a shared one — attack_sim_phase4.py's
# ensure_account() logs in if the account exists, signs up if not, so a never-before-seen
# random email always takes the signup path. No cleanup step is needed for the same reason
# scripts/attack_sim_realworld.py needs none: an account this script never revisits can't
# accumulate the cross-run leftover-evidence contamination documented in
# logs/redteam-daily.log (2026-09-27/09-30). Accepted trade-off: one throwaway account per
# month, never cleaned up — harmless on a local dev SQLite instance.

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/redteam-monthly-apt.log"
BASE_URL="http://localhost:8000"
HEALTH_URL="$BASE_URL/health"
DATE_STR="$(date +%Y-%m-%d)"

mkdir -p "$LOG_DIR"

RUN_ID="$(openssl rand -hex 4 2>/dev/null || date +%s%N | shasum | cut -c1-8)"
export AEGIS_EMAIL="redteam-apt-${RUN_ID}@cordon.local"
export AEGIS_PASSWORD="$(openssl rand -base64 24 2>/dev/null || echo "Monthly-APT-${RUN_ID}-Only!")"

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
    echo "[monthly_redteam_apt] ERROR: $*" >&2
    exit 1
}

cd "$PROJECT_ROOT" || fail "could not cd into project root ($PROJECT_ROOT)"

[ -f "$BACKEND_DIR/.venv/bin/activate" ] || fail "no venv at backend/.venv — run: cd backend && python3.11 -m venv .venv && pip install -e '.[dev]'"
# shellcheck disable=SC1091
source "$BACKEND_DIR/.venv/bin/activate"

if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    echo "[monthly_redteam_apt] backend already running at $BASE_URL"
else
    echo "[monthly_redteam_apt] starting backend locally..."
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
        echo "[monthly_redteam_apt] backend failed to become healthy within 60s; last log lines:" >&2
        tail -n 40 "$TMP_DIR/backend.log" >&2
        fail "backend did not respond on $HEALTH_URL"
    fi
    echo "[monthly_redteam_apt] backend healthy at $BASE_URL"
fi

echo "[monthly_redteam_apt] running attack_sim_phase4.py (nation-state/APT ceiling test)..."
python3 "$PROJECT_ROOT/scripts/attack_sim_phase4.py" --base-url "$BASE_URL" --pace 0 --no-prompt \
    >"$TMP_DIR/phase4.log" 2>&1
PHASE4_EXIT=$?
tail -n 30 "$TMP_DIR/phase4.log"

parse_rate() {
    grep -oE 'Detection rate: [0-9]+/[0-9]+' "$1" | head -1 | grep -oE '[0-9]+/[0-9]+'
}
parse_fp() {
    grep -oE 'False positives: [0-9]+' "$1" | head -1 | grep -oE '[0-9]+'
}

RATE="$(parse_rate "$TMP_DIR/phase4.log")"
FP="$(parse_fp "$TMP_DIR/phase4.log")"; FP="${FP:-0}"

if [ -z "$RATE" ]; then
    echo "[monthly_redteam_apt] WARNING: could not parse a detection rate out of attack_sim_phase4.py's output (exit=$PHASE4_EXIT); full output:" >&2
    cat "$TMP_DIR/phase4.log" >&2
    RATE="ERR"
fi

# Informational only — flags a false positive for visibility (this suite should still never
# misfire on benign activity, that bar doesn't relax for nation-state scenarios), but never
# gates: a low/zero detection rate against elite tradecraft is the EXPECTED ceiling, not a
# regression, so this never exits non-zero on rate alone the way daily_redteam.sh does.
NOTE=""
if [ "$FP" -gt 0 ]; then
    NOTE=" | NOTE: false positives are never expected even here — investigate"
fi

LOG_LINE="${DATE_STR} | ceiling-test (non-gating) | phase4-apt ${RATE} | false-positives: ${FP}${NOTE}"
echo "$LOG_LINE" >>"$LOG_FILE"
echo "[monthly_redteam_apt] $LOG_LINE"

exit 0
