#!/usr/bin/env bash
# Build each subject's verification harness as a libFuzzer binary (ASan + UBSan) with its LTL monitor linked in.
# Needs scripts/fetch.sh first. Output: work/out/<subject>/fuzzer
# usage: scripts/build.sh <subject>... | all
set -euo pipefail
cd "$(dirname "$0")/.."
[ "${1:-}" = all ] && set -- $(ls */source.json | cut -d/ -f1)
SAN=(-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g -w)

build_one() {
  local s=$1 B S O H std src o g i d l
  B=$s/build.json
  S=$PWD/work/src/$(basename "$(jq -r .repository "$s/source.json")")
  O=$PWD/work/out/$s
  [ -d "$S" ] || { echo "$s: run scripts/fetch.sh $s first" >&2; return 1; }
  rm -rf "$O"; mkdir -p "$O/obj"
  echo "== $s"

  # 1. LTL rules -> C monitor (preqed_ltl.c/.h); also replays every example trace in ltl.json
  node --experimental-strip-types --no-warnings tools/check-ltl.ts "$s/ltl.json" "$O"

  # 2. compile flags from build.json
  std=$(jq -r '.languageStandard // empty' "$B")
  F=(-I "$O" -I "$S")
  for i in $(jq -r '.includeRoots[]?' "$B"); do case $i in /*) F+=(-I "$i");; *) F+=(-I "$S/$i");; esac; done
  for g in $(jq -r '.includeRootGlobs[]?' "$B"); do for d in $S/$g; do [ -d "$d" ] && F+=(-I "$d"); done; done
  while IFS= read -r d; do F+=("-D$d"); done < <(jq -r '.preprocessorDefinitions[]?' "$B")
  L=(); for l in $(jq -r '.linkLibraries[]?' "$B"); do L+=("-l$l"); done
  cstd=(); xstd=(-std=c++17)
  case "$std" in c*+*) xstd=(-std="$std");; "") ;; *) cstd=(-std="$std");; esac

  # 3. library sources, the monitor, then the harness
  objs=()
  for src in $(jq -r '.implementationSources[]?' "$B"); do
    o=$O/obj/$(echo "$src" | tr / _).o
    case $src in
      *.c) clang "${cstd[@]}" "${F[@]}" "${SAN[@]}" -fsanitize=fuzzer-no-link -c "$S/$src" -o "$o" ;;
      *)   clang++ "${xstd[@]}" "${F[@]}" "${SAN[@]}" -fsanitize=fuzzer-no-link -c "$S/$src" -o "$o" ;;
    esac
    objs+=("$o")
  done
  clang -std=c11 "${SAN[@]}" -fsanitize=fuzzer-no-link -c "$O/preqed_ltl.c" -o "$O/obj/preqed_ltl.o"
  H=$s/harness.c; [ -f "$H" ] || H=$s/harness.cpp
  case $H in
    *.c) clang "${cstd[@]}" "${F[@]}" "${SAN[@]}" -fsanitize=fuzzer "$H" "${objs[@]}" "$O/obj/preqed_ltl.o" "${L[@]}" -lm -pthread -ldl -o "$O/fuzzer" ;;
    *)   clang++ "${xstd[@]}" "${F[@]}" "${SAN[@]}" -fsanitize=fuzzer "$H" "${objs[@]}" "$O/obj/preqed_ltl.o" "${L[@]}" -lm -pthread -ldl -o "$O/fuzzer" ;;
  esac
  rm -rf "$O/obj"
  echo "   built $O/fuzzer"
}

# each subject in its own subshell (errexit stays active there); keep going past failures
set +e
failed=()
for s in "$@"; do
  ( set -e; build_one "$s" )
  [ $? -eq 0 ] || { echo "   FAILED: $s" >&2; failed+=("$s"); }
done
[ ${#failed[@]} -eq 0 ] || { echo "not built: ${failed[*]}" >&2; exit 1; }
