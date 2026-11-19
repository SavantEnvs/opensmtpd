#!/usr/bin/env bash
#
# mayhem/test.sh — OpenSMTPD functional oracle (everything was built by mayhem/build.sh with the
# project's normal flags). Upstream ships no unit tests (its regress suite needs a running daemon),
# so the oracle is:
#   * mayhem/out/selftest — known-answer checks of smtpd's parsers (to.c, expand.c, envelope.c,
#     crypto.c, rfc5322.c, unpack_dns.c, srs.c, util.c), one TAP line per check;
#   * smtpd -n -f <conf> — the real daemon's config check on a valid and two invalid smtpd.conf,
#     asserting its verdict text.
# exit 0 = pass.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


OUT="$SRC/mayhem/out"
SMTPD="$SRC/mayhem/build/normal/mk/smtpd/smtpd"
for f in "$OUT/selftest" "$SMTPD"; do
  [ -x "$f" ] || { echo "missing $f — run mayhem/build.sh first" >&2; emit_ctrf "opensmtpd-selftest" 0 1 0; exit 1; }
done

passed=0 failed=0
pass() { echo "PASS: $1"; passed=$((passed + 1)); }
fail() { echo "FAIL: $1"; failed=$((failed + 1)); }

# 1) known-answer unit checks: count TAP lines, and require the expected number of them
EXPECTED_SELFTESTS=22
st_out=$("$OUT/selftest" 2>&1); st_rc=$?
echo "$st_out"
st_ok=$(grep -c '^ok ' <<<"$st_out" || true)
st_nok=$(grep -c '^not ok ' <<<"$st_out" || true)
passed=$((passed + st_ok)); failed=$((failed + st_nok))
if [ "$((st_ok + st_nok))" -ne "$EXPECTED_SELFTESTS" ] || [ "$st_rc" -ne 0 -a "$st_nok" -eq 0 ]; then
  fail "selftest ran $((st_ok + st_nok))/$EXPECTED_SELFTESTS checks (rc=$st_rc)"
fi

# 2) smtpd -n: the daemon's own configuration check
work=$(mktemp -d "${TMPDIR:-/tmp}/opensmtpd-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
printf 'root: bob\npostmaster: root\n' > "$work/aliases"
cat > "$work/good.conf" <<CONF
listen on lo
table aliases file:$work/aliases
action "local" mbox alias <aliases>
action "relay" relay host smtp://mx.example.org:2525
match from local for local action "local"
match from local for any action "relay"
CONF
printf 'listen on lo\nmatch from local for nonsense\n' > "$work/syntax.conf"
printf 'listen on lo\naction "local" mbox alias <nosuch>\nmatch from local for local action "local"\n' > "$work/table.conf"

out=$("$SMTPD" -n -f "$work/good.conf" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && grep -qx 'configuration OK' <<<"$out"; then pass "smtpd -n accepts a valid config"; else fail "smtpd -n valid config: rc=$rc out=$out"; fi

out=$("$SMTPD" -n -f "$work/syntax.conf" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && grep -q 'syntax.conf:2: syntax error' <<<"$out"; then pass "smtpd -n reports a syntax error with its line"; else fail "smtpd -n syntax error: rc=$rc out=$out"; fi

out=$("$SMTPD" -n -f "$work/table.conf" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && grep -q 'table.conf:2: no such table: nosuch' <<<"$out"; then pass "smtpd -n reports an undefined table"; else fail "smtpd -n undefined table: rc=$rc out=$out"; fi

emit_ctrf "opensmtpd-selftest" "$passed" "$failed" 0
