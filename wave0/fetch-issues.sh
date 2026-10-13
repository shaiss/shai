#!/usr/bin/env bash
# Emit one JSON object per line: {number,title,body,labels:[...]} for TARGET_REPO issues. Read-only.
set -euo pipefail
: "${TARGET_REPO:?}"
if [[ -n "${ISSUES:-}" ]]; then
  for n in $ISSUES; do
    [[ "$n" =~ ^[0-9]+$ ]] || { echo "bad issue number: $n" >&2; exit 2; }
    gh api "repos/${TARGET_REPO}/issues/${n}" \
      --jq '{number, title, body: (.body // "" | .[0:6000]), labels: [.labels[].name]}' | jq -c .
  done
else
  gh api "repos/${TARGET_REPO}/issues?state=open&per_page=20&sort=created" \
    --jq '.[] | select(.pull_request | not) | {number, title, body: (.body // "" | .[0:6000]), labels: [.labels[].name]}' | jq -c .
fi
