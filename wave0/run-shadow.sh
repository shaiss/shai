#!/usr/bin/env bash
# Shadow-run shai as a labeler. Appends rows to the agreement CSV. Never applies labels.
# On quota (429/402/credit limit) or a 5xx error: log the row and exit 0 (Cipher condition 3: no fallback).
set -euo pipefail

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
  echo "perms-check: ok (tools=$TOOLS)"
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

main() {
  local issues=$1 out=$2 model=${SHAI_MODEL:?SHAI_MODEL required}
  [[ -f "$out" ]] || echo "ts,model,issue,status,proposed,existing,jaccard,exact,latency_s,exit_code" >"$out"
  local allowed; allowed=$(grep -vE '^\s*(#|$)' "$ALLOWLIST" | paste -sd, -)
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
      if [[ $status == quota || $status == 5xx ]]; then
        echo "::warning::$status from provider on #$num ($model); logged and stopping (no fallback)."
        rm -f "$errf" "$outf"; exit 0
      fi
      rm -f "$errf" "$outf"; continue
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
    if [[ $proposed == __PARSE_ERROR__ ]]; then status=parse_error; proposed=""; j=",";
    else status=ok; j=$(jaccard "$proposed" "$existing"); fi
    echo "$(date -u +%FT%TZ),$model,$num,$status,$(csv_escape "$proposed"),$(csv_escape "$existing"),${j},${lat}," >>"$out"
    rm -f "$errf" "$outf"
  done <"$issues"
}

if [[ "${1:-}" == "--self-check" ]]; then self_check; exit 0; fi
[[ $# -eq 2 ]] || { echo "usage: $0 issues.jsonl out.csv | --self-check" >&2; exit 2; }
self_check >/dev/null
main "$1" "$2"
