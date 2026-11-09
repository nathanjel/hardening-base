#!/usr/bin/env bash
# hb — dispatcher. `hb <tool> [verb] [args]` runs tools/hb-<tool>; `hb check` runs
# every tool's check and prints one line per tool. Tools never call each other
# directly, only through this file.
set -u
HB_ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
export HB_ROOT

tools() {
  local t
  for t in "$HB_ROOT"/tools/hb-*; do
    [ -x "$t" ] && printf '%s\n' "${t##*/hb-}"
  done
}

case "${1:-help}" in
  help|-h|--help)
    echo "usage: hb <tool> [verb] [args]    e.g. hb k8s plan, hb health status"
    echo "       hb check                   one line per tool (exit 0 ok, 1 warn, 2 fail)"
    echo "tools: $(tools | tr '\n' ' ')"
    ;;
  check)
    worst=0 ok=0 warn=0 fail=0 idle=()
    for t in $(tools); do
      out="$("$HB_ROOT/tools/hb-$t" check 2>&1)"; rc=$?
      out="${out##*$'\n'}"   # a check's verdict is its last line
      # exit 1 is a warning only with a verdict that says so: Python exits 1 on an uncaught
      # exception and bash on an unbound variable, and a check that broke is a failure
      if [ "$rc" -eq 1 ]; then case "$out" in warn*|pending*) ;; *) rc=2 out="fail: the check broke: $out" ;; esac; fi
      printf '%-10s %s\n' "$t" "$out"
      [ "$rc" -gt "$worst" ] && worst=$rc
      case "$rc" in 0) ok=$((ok + 1)) ;; 1) warn=$((warn + 1)) ;; *) fail=$((fail + 1)) ;; esac
      # an "ok" that only means the tool has nothing to do here: green, but nothing is being checked.
      # Its first clause says so ("ok: not configured"); a later one may be about another tool
      # (the digest's "backup not configured")
      case "${out%%;*}" in "ok: "*"not managed"*|"ok: "*"not configured"*|"ok: "*"not installed"*) idle+=("$t") ;; esac
    done
    printf '\n%d ok, %d warn, %d fail' "$ok" "$warn" "$fail"
    [ ${#idle[@]} -gt 0 ] && printf '; not managed here: %s' "$(IFS=,; echo "${idle[*]}" | sed 's/,/, /g')"
    printf '\n'
    [ "$worst" -gt 2 ] && worst=2
    exit "$worst"
    ;;
  *)
    t="$HB_ROOT/tools/hb-$1"
    [ -x "$t" ] || { echo "hb: no tool '$1' (try: hb help)" >&2; exit 2; }
    shift
    exec "$t" "$@"
    ;;
esac
