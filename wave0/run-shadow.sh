#!/usr/bin/env bash
# Shadow-run shai as a labeler. Appends rows to the agreement CSV. Never applies labels.
# On a transient quota (429) or 5xx error: log the row and exit 0 (Cipher condition 3: no fallback).
# Out of credits (HTTP 402 / insufficient credits): log the row and exit 1 so the job goes red.
set -euo pipefail
# Cipher: OVH_API_KEY must never be set (shai's anonymous-OVH path would send it). Record, then drop it.
OVH_KEY_WAS_SET=${OVH_API_KEY+1}
unset OVH_API_KEY

SHAI_BIN="${SHAI_BIN:-./shai}"
TOOLS="read,ls,find"                  # Cipher condition 3: no fetch. Names verified against `shai --list-tools` (v0.2.2)
FORBIDDEN_TOOLS="fetch bash edit write memory_write memory_remove todo_write skills"
ALLOWLIST="${ALLOWLIST:-$(dirname "$0")/labels-allowlist.txt}"

# shellcheck disable=SC2016  # literal source patterns on purpose
self_check() {
  local t
  for t in ${TOOLS//,/ }; do
    for f in $FORBIDDEN_TOOLS; do
      [[ "$t" == "$f" ]] && { echo "perms-check: forbidden tool $t" >&2; exit 1; }
    done
  done
  # Every line that invokes the shai binary must not pass -a/--agent (it would bypass --tools).
  if grep -F '"$SHAI_BIN" --' "$0" | grep -qE -- '[[:space:]](-a|--agent)([[:space:]=]|$)'; then
    echo "perms-check: shai invoked with --agent" >&2; exit 1
  fi
  grep -qF '"$SHAI_BIN" --tools "$TOOLS"' "$0" || { echo "perms-check: shai call missing --tools" >&2; exit 1; }
  [[ ",$TOOLS," == *",fetch,"* ]] && { echo "perms-check: fetch must be absent" >&2; exit 1; }
  [[ -z ${OVH_KEY_WAS_SET:-} ]] || { echo "perms-check: OVH_API_KEY is set in the environment; refusing" >&2; exit 1; }
  # Provider pin (Cipher cond. 2): check what shai ACTUALLY resolves, not env vars. Fail closed.
  # Model resolution (shai v0.2.2): ShaiConfig::get_llm loads auth.config.json, then
  # set_env_vars() copies providers[selected].model into SHAI_MODEL, then
  # LlmClient::default_model() returns SHAI_MODEL. The config `model` field is NOT ignored.
  local cfg="${XDG_CONFIG_HOME:-$HOME/.config}/shai/auth.config.json" model=${SHAI_MODEL:?SHAI_MODEL required} banner
  [[ -f "$cfg" ]] || { echo "perms-check: missing $cfg" >&2; exit 1; }
  # Offline probe: dummy key, proxies pointed at a dead port so no request can leave the runner.
  # shai prints "<model> on <provider>" to stderr for the config it actually loaded.
  banner=$(printf 'selfcheck' | env -i PATH="$PATH" HOME="${HOME:-/tmp}" XDG_CONFIG_HOME="${cfg%/shai/auth.config.json}" \
    OPENROUTER_API_KEY=selfcheck-dummy HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
    NO_PROXY= timeout 30 "$SHAI_BIN" --tools "$TOOLS" 2>&1 >/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -m1 ' on ' || true)
  if grep -qi 'failed to parse config' <<<"$banner" || [[ "$banner" != *" $model on openrouter"* ]]; then
    echo "perms-check: shai resolves to '${banner#* }', expected '$model on openrouter'" >&2; exit 1
  fi
  echo "perms-check: ok (tools=$TOOLS, resolved: $model on openrouter)"
}

csv_escape() { local s=${1//\"/\"\"}; printf '"%s"' "${s//$'\n'/ }"; }

jaccard() { # $1,$2: comma lists -> prints jaccard,exact
  python3 - "$1" "$2" <<'PY'
import sys
a={x for x in sys.argv[1].split(',') if x}; b={x for x in sys.argv[2].split(',') if x}
u=a|b; print(f"{(len(a&b)/len(u) if u else 1.0):.3f},{int(a==b)}")
PY
}

classify_error() { # stderr text -> credits|quota|5xx|other
  # Order matters: an explicit 402 is out of credits; 429/rate-limit text is transient even when
  # it mentions credits (OpenRouter: "Rate limit exceeded ... Add 10 credits to unlock ...").
  if grep -qiE '(^|[^0-9])402([^0-9]|$)' <<<"$1"; then echo credits
  elif grep -qiE '(^|[^0-9])429([^0-9]|$)|rate.?limit|too many requests' <<<"$1"; then echo quota
  elif grep -qiE 'requires more credits|insufficient (credits|funds)|credit limit' <<<"$1"; then echo credits
  elif grep -qiE 'quota' <<<"$1"; then echo quota
  elif grep -qiE '(^|[^0-9])5[0-9]{2}([^0-9]|$)|bad gateway|service unavailable|gateway timeout' <<<"$1"; then echo 5xx
  else echo other; fi
}

key_usage() { # prints OpenRouter key usage; key goes to curl via stdin config, never argv or logs
  printf 'header = "Authorization: Bearer %s"\n' "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY required}" \
    | curl -fsS --max-time 20 -K - "${OPENROUTER_KEY_URL:-https://openrouter.ai/api/v1/key}" | jq -er '.data.usage'
}

usage_increased() { python3 -c 'import sys; sys.exit(0 if float(sys.argv[2])>float(sys.argv[1]) else 1)' "$1" "$2"; }

# Canary deadline. OpenRouter settles a request's cost a little after it finishes, and the
# key usage it reports can lag further (observed 16-26 s, once more than 30 s), so poll until
# a deadline rather than for a fixed few tries. Still fails hard if usage never moves.
# Unset -> default; set but empty/invalid -> main() refuses before any call (fail closed).
CANARY_WAIT_S=${CANARY_WAIT_S-120}
CANARY_POLL_S=${CANARY_POLL_S-10}

check_canary_secs() { # $1=name $2=value: whole seconds, 1..3600, no sign/decimals/leading zero
  if [[ ! $2 =~ ^[1-9][0-9]{0,3}$ ]] || (( $2 > 3600 )); then
    echo "::error::$1 must be a whole number of seconds from 1 to 3600 (got '$2'); refusing to run"
    exit 1
  fi
}

# Best-effort OpenRouter generation id (the response `id`) from shai's output, for looking a
# call up on OpenRouter later. Prints "unavailable" when shai did not print one (shai v0.2.2
# does not). Only the id is extracted; nothing else from the output is logged.
# Shape: OpenRouter's GET /api/v1/generation reference gives the id pattern ^gen-[0-9A-Za-z-]+$
# (max 128) with example "gen-3bhGkxlo4XFrqiabUM7NDtwDzWwG"; live responses use
# "gen-<10-digit unix time>-<alphanumerics>". Accept exactly those two forms as a whole token:
#   gen-<10 digits>-<16..40 alnum>   or   gen-<20..64 alnum>
GEN_ID_RE='gen-([0-9]{10}-[0-9A-Za-z]{16,40}|[0-9A-Za-z]{20,64})'
gen_id_of() {
  local g; g=$(grep -ohE "(^|[^0-9A-Za-z_-])${GEN_ID_RE}([^0-9A-Za-z_-]|\$)" "$@" 2>/dev/null \
    | tail -n1 | grep -oE "$GEN_ID_RE" || true)
  printf '%s' "${g:-unavailable}"
}

llm_error_text() { grep -qiE 'LLM error|rate.?limit|too many requests|(^|[^0-9])(429|402)([^0-9]|$)|quota|requires more credits' "$1"; }

failure_type() { # $1 stdout file, $2 stderr file -> empty|ratelimit_text|no_json. Never echoes content.
  if grep -qiE 'rate.?limit|too many requests|(^|[^0-9])429([^0-9]|$)|quota' "$1" "$2"; then echo ratelimit_text
  elif [[ ! -s "$1" ]] || ! grep -q '[^[:space:]]' "$1"; then echo empty
  else echo no_json; fi
}

check_failure_budget() { # uses attempted/failed/consec from main
  if (( consec >= 3 )) || { (( attempted >= 4 )) && (( failed * 4 > attempted )); }; then
    echo "::error::failure budget exceeded ($failed/$attempted failed, $consec consecutive); aborting"
    exit 1
  fi
}

# Issue #10: abort when too many successful parses still yield empty allow-listed labels.
# "More than 75%" with integers: empty_rows * 4 > attempted * 3 (so 3/4 empty is OK, 4/4 fails).
check_all_empty_alarm() { # $1=attempted $2=empty_rows → return 1 if trip
  local attempted=$1 empty_rows=$2
  if (( attempted >= 4 )) && (( empty_rows * 4 > attempted * 3 )); then
    echo "::error::all-empty alarm: ${empty_rows}/${attempted} attempts returned empty allow-listed labels (>75%); aborting"
    return 1
  fi
  return 0
}

# Issue #14 L1: every finished row without allow-listed labels counts toward the alarm:
# ok-but-empty, parse_error, llm_error and other errors (an error proposes nothing).
tally_alarm() { # $1=status $2=proposed; updates empty_rows from the caller's scope
  if [[ $1 != ok || -z $2 ]]; then empty_rows=$((empty_rows + 1)); fi
}

# Provider stop: no fallback (Cipher condition 3). Issue #14 L2: run the alarm first in
# every path so "N empty rows then a 429" is not reported green. Always exits.
# credits (402, out of money) exits 1: the account needs a top-up, so the job must go red.
# quota (429) / 5xx are transient: exit 0 with a warning unless the alarm trips.
provider_stop() { # $1=credits|quota|5xx $2=issue; uses attempted/empty_rows from the caller
  local alarm=0
  check_all_empty_alarm "$attempted" "$empty_rows" || alarm=1
  if [[ $1 == credits ]]; then
    echo "::error::out of credits (HTTP 402) from provider on #$2 (${SHAI_MODEL:-?}); logged and stopping (no fallback). Top up the OpenRouter account."
    exit 1
  fi
  echo "::warning::$1 from provider on #$2 (${SHAI_MODEL:-?}); logged and stopping (no fallback)."
  (( alarm == 0 )) || exit 1
  exit 0
}

is_provider_stop() { [[ $1 == credits || $1 == quota || $1 == 5xx ]]; }

main() {
  local issues=$1 out=$2 model=${SHAI_MODEL:?SHAI_MODEL required}
  check_canary_secs CANARY_WAIT_S "$CANARY_WAIT_S"; check_canary_secs CANARY_POLL_S "$CANARY_POLL_S"
  [[ -f "$out" ]] || echo "ts,model,issue,status,proposed,existing,jaccard,exact,latency_s,exit_code" >"$out"
  local allowed; allowed=$(grep -vE '^\s*(#|$)' "$ALLOWLIST" | paste -sd, -)
  local first=1 usage0 usage1 i attempted=0 failed=0 consec=0 empty_rows=0
  usage0=$(key_usage) || { echo "::error::canary: cannot read key usage before first issue; aborting"; exit 1; }
  while IFS= read -r line; do
    local num title body existing prompt t0 rc errf outf proposed status j
    num=$(jq -r .number <<<"$line"); title=$(jq -r .title <<<"$line"); body=$(jq -r .body <<<"$line")
    existing=$(jq -r '.labels | sort | join(",")' <<<"$line")
    prompt=$(printf 'You are an issue labeler. Allowed labels: %s\nReturn ONLY JSON: {"labels":[...],"reason":"..."} using only allowed labels.\n\nTITLE: %s\n\nBODY:\n%s\n' "$allowed" "$title" "$body")
    errf=$(mktemp); outf=$(mktemp); t0=$(date +%s)
    set +e
    printf '%s' "$prompt" | timeout 300 "$SHAI_BIN" --tools "$TOOLS" --temperature 0 >"$outf" 2>"$errf"
    rc=$?; set -e
    local lat=$(( $(date +%s) - t0 )); proposed=""
    echo "call: issue=#$num model=$model rc=$rc latency_s=$lat gen_id=$(gen_id_of "$errf" "$outf")"
    if [[ $rc -ne 0 ]]; then
      status=$(classify_error "$(cat "$errf" "$outf")")
      # Cipher condition 4: no raw output in the CSV, only the error class and exit code.
      echo "$(date -u +%FT%TZ),$model,$num,$status,,$(csv_escape "$existing"),,,${lat},$rc" >>"$out"
      rm -f "$errf" "$outf"
      if is_provider_stop "$status"; then provider_stop "$status" "$num"; fi
      attempted=$((attempted+1)); tally_alarm "$status" ""
      failed=$((failed+1)); consec=$((consec+1)); check_failure_budget; continue
    fi
    # Pull the last JSON object with a labels array; keep only allow-listed labels.
    proposed=$(python3 - "$outf" "$allowed" <<'PY'
import json,re,sys
txt=open(sys.argv[1]).read(); allowed=set(sys.argv[2].split(','))
for m in reversed(list(re.finditer(r'\{[^{}]*"labels"[^{}]*\}', txt, re.S))):
    try: d=json.loads(m.group(0)); break
    except Exception: pass
else: print("__PARSE_ERROR__"); sys.exit()
print(",".join(sorted(l for l in d.get("labels",[]) if l in allowed)))
PY
)
    attempted=$((attempted+1))
    # shai exits 0 on LLM errors. Only treat as llm_error/parse_error when JSON
    # parse failed (__PARSE_ERROR__). An empty allow-listed label list after a
    # successful parse is still status=ok (Bugbot: empty labels ≠ call failure).
    if [[ $proposed == __PARSE_ERROR__ ]]; then
      if llm_error_text "$errf" || llm_error_text "$outf"; then
        # shai v0.2.2 exits 0 on provider errors, so classify them here too (labeler run
        # 39319608521: an rc=0 HTTP 402 was logged as llm_error and only the canary caught it).
        local pstatus; pstatus=$(classify_error "$(cat "$errf" "$outf")")
        if is_provider_stop "$pstatus"; then
          echo "$(date -u +%FT%TZ),$model,$num,$pstatus,,$(csv_escape "$existing"),,,${lat},0" >>"$out"
          rm -f "$errf" "$outf"; attempted=$((attempted-1))   # not an attempt, same as the rc != 0 path
          provider_stop "$pstatus" "$num"
        fi
        status=llm_error; proposed=""; j=","
        echo "call-failure: issue=#$num model=$model type=$(failure_type "$outf" "$errf") stdout_bytes=$(wc -c <"$outf") stderr_bytes=$(wc -c <"$errf")" >&2
      else
        status=parse_error; proposed=""; j=","
        # Job log only (never the CSV, never raw output): failure class + byte count.
        echo "parse-failure: issue=#$num model=$model type=$(failure_type "$outf" "$errf") stdout_bytes=$(wc -c <"$outf") stderr_bytes=$(wc -c <"$errf")" >&2
      fi
    else
      status=ok; j=$(jaccard "$proposed" "$existing")
    fi
    # Empty allow-listed list is still ok for a single issue, but counts for the #10 alarm.
    tally_alarm "$status" "$proposed"
    echo "$(date -u +%FT%TZ),$model,$num,$status,$(csv_escape "$proposed"),$(csv_escape "$existing"),${j},${lat}," >>"$out"
    rm -f "$errf" "$outf"
    if [[ $status == ok ]]; then consec=0; else failed=$((failed+1)); consec=$((consec+1)); check_failure_budget; fi
    if (( first )); then # canary: the first call must bill this key, else shai is not using it
      first=0; usage1=""; i=0
      local c0 cnow; c0=$(date +%s)
      while :; do
        i=$((i+1)); usage1=$(key_usage) || usage1=""
        [[ -n $usage1 ]] && usage_increased "$usage0" "$usage1" && break
        cnow=$(date +%s)
        (( cnow - c0 >= CANARY_WAIT_S )) && break
        # Never sleep past the deadline, so the last poll lands on it.
        sleep $(( CANARY_POLL_S < CANARY_WAIT_S - (cnow - c0) ? CANARY_POLL_S : CANARY_WAIT_S - (cnow - c0) ))
      done
      cnow=$(date +%s)
      if [[ -z $usage1 ]] || ! usage_increased "$usage0" "$usage1"; then
        echo "::error::canary: key usage did not increase after issue #$num ($usage0 -> ${usage1:-?}, elapsed $((cnow - c0))s of ${CANARY_WAIT_S}s, poll $i); aborting"
        exit 1
      fi
      echo "canary: ok (usage $usage0 -> $usage1, elapsed $((cnow - c0))s, poll $i)"
    fi
  done <"$issues"
  check_all_empty_alarm "$attempted" "$empty_rows" || exit 1
}

if [[ "${1:-}" == "--self-check" ]]; then self_check; exit 0; fi
# Offline replay of real provider errors through main(), for --test-all-empty-alarm.
# A fake shai prints a recorded stderr and exits with a chosen code; key usage is read from a
# file:// URL with a dummy key. No network, no real key, no shai binary.
test_provider_errors_replay() {
  local d; d=$(mktemp -d)
  cat >"$d/fake-shai" <<'SH'
#!/usr/bin/env bash
cat >/dev/null
# Slow-settling counter: bump key usage FAKE_BUMP_AFTER seconds after the call returns.
if [[ -n ${FAKE_BUMP_AFTER:-} ]]; then
  nohup bash -c 'sleep "$1"; printf "%s\n" "{\"data\":{\"usage\":1.5}}" >"$2.tmp" && mv "$2.tmp" "$2"' _ \
    "$FAKE_BUMP_AFTER" "$FAKE_KEY_FILE" >/dev/null 2>&1 &
fi
[[ -z ${FAKE_STDOUT:-} ]] || cat "$FAKE_STDOUT"
[[ -z ${FAKE_STDERR:-} ]] || cat "$FAKE_STDERR" >&2
exit "${FAKE_RC:-0}"
SH
  chmod +x "$d/fake-shai"
  echo '{"data":{"usage":1.0}}' >"$d/key.json"
  echo '{"number":859,"title":"t","body":"b","labels":["bug"]}' >"$d/issues.jsonl"
  # Sanitised from labeler run 39319608521 (google/gemini-3.8-flash on OpenRouter).
  printf '%s\n' '● Error: LLM error: 402: {"error":{"message":"This request requires more credits, or fewer max_tokens. You requested up to 65536 tokens, but can only afford 5598.","code":402,"metadata":{"limit_source":"openrouter_credits"}}}' >"$d/e402"
  printf '%s\n' '● Error: LLM error: 429: {"error":{"message":"Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests per day","code":429}}' >"$d/e429"
  replay() { # $1=stderr fixture $2=fake rc $3=want exit $4=want CSV status $5=want log text
    local rc log row
    rm -f "$d/out.csv"
    set +e
    # shellcheck disable=SC2030,SC2031  # exports are meant to stay inside this subshell
    log=$( (export SHAI_BIN="$d/fake-shai" SHAI_MODEL=test/model OPENROUTER_API_KEY=offline-dummy \
              OPENROUTER_KEY_URL="file://$d/key.json" FAKE_STDERR="$d/$1" FAKE_RC="$2"
            main "$d/issues.jsonl" "$d/out.csv") 2>&1 ); rc=$?
    set -e
    row=$(sed -n 2p "$d/out.csv" | cut -d, -f4)
    if [[ $rc -ne $3 || $row != "$4" ]] || ! grep -q -- "$5" <<<"$log"; then
      echo "FAIL: replay $1 rc=$2 -> exit $rc status '$row' (want exit $3 status '$4' log '$5')"; exit 1
    fi
  }
  replay e402 0 1 credits '::error::out of credits'   # shai exit 0 + 402: credits row, red job
  replay e429 0 0 quota   '::warning::quota'          # shai exit 0 + 429: existing quota stop
  replay e402 1 1 credits '::error::out of credits'   # nonzero exit + 402: same
  replay e429 1 0 quota   '::warning::quota'          # nonzero exit + 429: unchanged
  test_canary_deadline "$d"
  rm -rf "$d"
}

# Canary deadline: a successful call, then key usage that settles late, never, or too late.
test_canary_deadline() { # $1=scratch dir from test_provider_errors_replay
  local d=$1
  printf '%s\n' '{"labels":["bug"],"reason":"r"}' >"$d/ok.out"
  printf '%s\n' 'id: gen-1729000000-AbCdEfGhIjKlMnOpQrSt' >"$d/gen.err"        # live-response form
  printf '%s\n' 'id: gen-3bhGkxlo4XFrqiabUM7NDtwDzWwG' >"$d/gendoc.err"          # API-reference example
  printf '%s\n' 'see gen-ai-toolkit-v2, xgen-1729000000-AbCdEfGhIjKlMnOpQrSt, gen-1234567890, gen-1729000000-AbCdEfGhIjKlMnOpQrSt_x' >"$d/lookalike.err"
  local n=0 log=""
  : >"$d/none.err"
  canary() { # $1=bump after (s, "" = never) $2=wait s $3=want exit $4=want log text $5=stderr fixture [$6=poll s]
    local rc k
    # A fresh key file per case: a late bump left over from an earlier case writes to that
    # case's file and can never satisfy this one.
    n=$((n+1)); k="$d/key.$n.json"
    rm -f "$d/out.csv"; echo '{"data":{"usage":1.0}}' >"$k"
    set +e
    # shellcheck disable=SC2030,SC2031  # exports are meant to stay inside this subshell
    log=$( (export SHAI_BIN="$d/fake-shai" SHAI_MODEL=test/model OPENROUTER_API_KEY=offline-dummy \
              OPENROUTER_KEY_URL="file://$k" FAKE_KEY_FILE="$k" FAKE_BUMP_AFTER="$1" \
              FAKE_STDOUT="$d/ok.out" FAKE_STDERR="$d/$5" FAKE_RC=0 CANARY_WAIT_S="$2" CANARY_POLL_S="${6-1}"
            main "$d/issues.jsonl" "$d/out.csv") 2>&1 ); rc=$?
    set -e
    if [[ $rc -ne $3 ]] || ! grep -q -- "$4" <<<"$log" || grep -q 'offline-dummy' <<<"$log"; then
      echo "FAIL: canary bump=${1:-never} wait=$2 -> exit $rc (want exit $3 log '$4')"; exit 1
    fi
  }
  canary 3 10 0 'canary: ok (usage 1.0 -> 1.5, elapsed '  gen.err   # slow settle (3 s) passes
  canary 3 10 0 'gen_id=gen-1729000000-AbCdEfGhIjKlMnOpQrSt' gen.err    # generation id logged
  canary 0 10 0 'gen_id=gen-3bhGkxlo4XFrqiabUM7NDtwDzWwG'  gendoc.err  # API-reference id form
  canary 0 10 0 'gen_id=unavailable'                      lookalike.err  # look-alikes rejected
  canary 0 10 0 'gen_id=unavailable'                      none.err  # no id printed: say so
  canary "" 3 1 '::error::canary: key usage did not increase after issue #859 (1.0 -> 1.0, elapsed ' none.err  # never moves: red
  canary 6 2 1 'elapsed [0-9]*s of 2s'                    none.err  # settles after the deadline: red
  canary 4 2 1 'elapsed 2s of 2s, poll 2'                 none.err 10  # poll > wait: sleep clamps to the deadline
  # Invalid timing values fail closed before any call (no "call:" line, no CSV data row).
  local v name
  for name in CANARY_WAIT_S CANARY_POLL_S; do
    for v in 0 -5 "" abc 1.5 010 3601; do
      if [[ $name == CANARY_WAIT_S ]]; then canary 0 "$v" 1 "::error::CANARY_WAIT_S must be a whole number" none.err
      else canary 0 5 1 "::error::CANARY_POLL_S must be a whole number" none.err "$v"; fi
      if grep -q '^call:' <<<"$log" || [[ -e $d/out.csv ]]; then
        echo "FAIL: $name='$v' must refuse before any call"; exit 1
      fi
    done
  done
}

if [[ "${1:-}" == "--test-all-empty-alarm" ]]; then
  # Stand-in unit checks for issue #10 (no network, no key).
  # Usage: $0 --test-all-empty-alarm
  set +e
  out=$(check_all_empty_alarm 4 4 2>&1); rc=$?; set -e
  if [[ $rc -ne 1 ]] || ! grep -q 'all-empty alarm' <<<"$out"; then
    echo "FAIL: all-empty (4/4) should abort"; exit 1
  fi
  set +e
  out=$(check_all_empty_alarm 4 3 2>&1); rc=$?; set -e
  if [[ $rc -ne 0 ]]; then echo "FAIL: 3/4 empty should be ok (not >75%)"; exit 1; fi
  set +e
  out=$(check_all_empty_alarm 8 5 2>&1); rc=$?; set -e
  if [[ $rc -ne 0 ]]; then echo "FAIL: 5/8 empty (62.5%) should be ok"; exit 1; fi
  set +e
  out=$(check_all_empty_alarm 8 7 2>&1); rc=$?; set -e
  if [[ $rc -ne 1 ]] || ! grep -q 'all-empty alarm' <<<"$out"; then
    echo "FAIL: 7/8 empty should abort"; exit 1
  fi
  set +e
  out=$(check_all_empty_alarm 3 3 2>&1); rc=$?; set -e
  if [[ $rc -ne 0 ]]; then echo "FAIL: attempted<4 should not trip"; exit 1; fi
  # Issue #14: drive the same tally_alarm/provider_stop helpers main() uses.
  # Tokens: label=ok with labels, empty=ok with no labels, parse_error|llm_error|other, credits|quota|5xx.
  simulate() {
    local attempted=0 empty_rows=0 s
    for s in "$@"; do
      case $s in
        credits|quota|5xx) provider_stop "$s" sim ;;
        label) attempted=$((attempted+1)); tally_alarm ok bug ;;
        empty) attempted=$((attempted+1)); tally_alarm ok "" ;;
        *) attempted=$((attempted+1)); tally_alarm "$s" "" ;;
      esac
    done
    check_all_empty_alarm "$attempted" "$empty_rows" || exit 1
    exit 0
  }
  expect() { # $1=want rc, rest=rows
    local want=$1 rc; shift
    set +e; out=$( (simulate "$@") 2>&1 ); rc=$?; set -e
    if [[ $rc -ne $want ]]; then echo "FAIL: [$*] expected rc=$want got rc=$rc"; exit 1; fi
  }
  expect 1 empty empty empty parse_error         # L1: 3 empty + 1 error of 4 aborts
  expect 1 empty empty empty llm_error
  expect 1 empty empty empty other
  expect 0 label empty empty parse_error         # 3/4 without labels is not >75%
  expect 1 empty empty empty empty empty empty empty quota   # L2: 7 empty then 429 aborts
  expect 1 empty empty empty empty 5xx           # L2: 5xx path also runs the alarm
  expect 0 label label label label empty quota   # healthy run then quota stays exit 0
  expect 0 empty empty quota                     # attempted<4 before quota: no trip
  expect 1 credits                               # 402 out of credits is always red
  expect 1 label label label label credits       # ...even after a healthy run
  set +e; out=$( (simulate empty empty empty empty empty empty empty credits) 2>&1 ); set -e
  if ! grep -q 'all-empty alarm' <<<"$out"; then echo "FAIL: alarm must run before the credits stop"; exit 1; fi
  for c in "LLM error: 402: requires more credits:credits" "LLM error: 429: Rate limit exceeded. Add 10 credits to unlock:quota" \
           "LLM error: 503 Service Unavailable:5xx" "insufficient credits:credits" "LLM error: boom:other" \
           "LLM error: 402: Payment Required:credits" "LLM error: 429: credit limit for free models:quota"; do
    got=$(classify_error "${c%:*}")
    if [[ $got != "${c##*:}" ]]; then echo "FAIL: classify_error '${c%:*}' -> $got, want ${c##*:}"; exit 1; fi
  done
  test_provider_errors_replay
  echo "ok: all-empty alarm stand-in tests passed"
  exit 0
fi
[[ $# -eq 2 ]] || { echo "usage: $0 issues.jsonl out.csv | --self-check | --test-all-empty-alarm" >&2; exit 2; }
self_check >/dev/null
main "$1" "$2"
