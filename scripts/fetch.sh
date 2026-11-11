#!/usr/bin/env bash
# Fetch each subject's library at its pinned commit into work/src/, then copy the subject's overlay/ in.
# usage: scripts/fetch.sh <subject>... | all
set -uo pipefail
cd "$(dirname "$0")/.."
[ "${1:-}" = all ] && set -- $(ls */source.json | cut -d/ -f1)

# clone <repository> <commit> <dir>: shallow fetch of the commit, full clone if the server refuses that
clone() {
  local repo=$1 sha=$2 dir=$3
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$sha" ]; then return; fi
  rm -rf "$dir"; mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" remote add origin "$repo"
  if ! git -C "$dir" fetch -q --depth 1 origin "$sha" 2>/dev/null; then
    git -C "$dir" fetch -q origin
  fi
  git -C "$dir" -c advice.detachedHead=false checkout -q "$sha"
}

fetch_one() {
  local s=$1 j=$1/source.json repo sha dir n i m
  repo=$(jq -r .repository "$j"); sha=$(jq -r .commit "$j")
  dir=work/src/$(basename "$repo")
  echo "== $s: $repo @ ${sha:0:12}"
  clone "$repo" "$sha" "$dir" || return 1
  for m in $(jq -r '.submodules[]?' "$j"); do
    git -C "$dir" submodule update -q --init --depth 1 -- "$m" || return 1
  done
  n=$(jq '.extra // [] | length' "$j")
  for ((i = 0; i < n; i++)); do
    clone "$(jq -r ".extra[$i].repository" "$j")" "$(jq -r ".extra[$i].commit" "$j")" "$dir/$(jq -r ".extra[$i].path" "$j")" || return 1
  done
  if [ -d "$s/overlay" ]; then cp -r "$s/overlay/." "$dir/"; fi
}

failed=()
for s in "$@"; do
  fetch_one "$s" || { echo "   FAILED: $s (repository or commit not reachable)" >&2; failed+=("$s"); }
done
[ ${#failed[@]} -eq 0 ] || { echo "not fetched: ${failed[*]}" >&2; exit 1; }
