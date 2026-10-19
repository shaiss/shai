#!/usr/bin/env bash
# Shadow-run shai as a labeler. Appends rows to the agreement CSV. Never applies labels.
# On quota (429/402/credit limit) or a 5xx error: log the row and exit 0 (Cipher condition 3: no fallback).
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

classify_error() { # stderr text -> quota|5xx|other
  if grep -qiE '(^|[^0-9])(429|402)([^0-9]|$)|rate.?limit|quota|insufficient (credits|funds)|credit limit' <<<"$1"; then echo quota
  elif grep -qiE '(^|[^0-9])5[0-9]{2}([^0-9]|$)|bad gateway|service unavailable|gateway timeout' <<<"$1"; then echo 5xx
  else echo other; fi
}

key_usage() { # prints OpenRouter key usage; key goes to curl via stdin config, never argv or logs
  printf 'header = "Authorization: Bearer %s"\n' "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY required}" \
    | curl -fsS --max-time 20 -K - "${OPENROUTER_KEY_URL:-https://openrouter.ai/api/v1/key}" | jq -er '.data.usage'
}

usage_increased() { python3 -c 'import sys; sys.exit(0 if float(sys.argv[2])>float(sys.argv[1]) else 1)' "$1" "$2"; }

llm_error_text() { grep -qiE 'LLM error|rate.?limit|too many requests|(^|[^0-9])429([^0-9]|$)|quota' "$1"; }

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

# Quota/5xx stop: no fallback (Cipher condition 3), but issue #14 L2: run the alarm
# first so "N empty rows then a 429" is not reported green. Always exits.
provider_stop() { # $1=status $2=issue; uses attempted/empty_rows from the caller
  echo "::warning::$1 from provider on #$2 (${SHAI_MODEL:-?}); logged and stopping (no fallback)."
  check_all_empty_alarm "$attempted" "$empty_rows" || exit 1
  exit 0
}

main() {
  local issues=$1 out=$2 model=${SHAI_MODEL:?SHAI_MODEL required}
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
    if [[ $rc -ne 0 ]]; then
      status=$(classify_error "$(cat "$errf" "$outf")")
      # Cipher condition 4: no raw output in the CSV, only the error class and exit code.
      echo "$(date -u +%FT%TZ),$model,$num,$status,,$(csv_escape "$existing"),,,${lat},$rc" >>"$out"
      rm -f "$errf" "$outf"
      if [[ $status == quota || $status == 5xx ]]; then provider_stop "$status" "$num"; fi
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
      first=0; usage1=""
      for i in 1 2 3 4 5 6; do
        usage1=$(key_usage) || usage1=""
        [[ -n $usage1 ]] && usage_increased "$usage0" "$usage1" && break
        sleep 5
      done
      if [[ -z $usage1 ]] || ! usage_increased "$usage0" "$usage1"; then
        echo "::error::canary: key usage did not increase after issue #$num ($usage0 -> ${usage1:-?}, try $i); aborting"
        exit 1
      fi
      echo "canary: ok (usage $usage0 -> $usage1)"
    fi
  done <"$issues"
  check_all_empty_alarm "$attempted" "$empty_rows" || exit 1
}

if [[ "${1:-}" == "--self-check" ]]; then self_check; exit 0; fi
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
  # Tokens: label=ok with labels, empty=ok with no labels, parse_error|llm_error|other, quota|5xx.
  simulate() {
    local attempted=0 empty_rows=0 s
    for s in "$@"; do
      case $s in
        quota|5xx) provider_stop "$s" sim ;;
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
  echo "ok: all-empty alarm stand-in tests passed"
  exit 0
fi
[[ $# -eq 2 ]] || { echo "usage: $0 issues.jsonl out.csv | --self-check | --test-all-empty-alarm" >&2; exit 2; }
self_check >/dev/null
main "$1" "$2"
