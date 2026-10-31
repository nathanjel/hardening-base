# Shared helpers for hb's bash tools. Source it, don't run it.
#
# A tool lists its ITEMS and defines two functions per item:
#   chk_<item>  print one line of detail, then return
#                 0  the system matches the config
#                 1  apply would change something
#                 2  broken in a way apply can't fix; needs a human
#   fix_<item>  make the change; only called right after chk returned 1
# run_items then provides the shared verbs: check, status, plan, apply.

HB_ROOT="${HB_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HB_STATE="${HB_STATE:-/var/lib/hb}"
HB_RUN="${HB_RUN:-$(date +%Y%m%d-%H%M%S)}"
HB_YES="${HB_YES:-0}"
export HB_ROOT
umask 077   # backups of config files and old homes are for root's eyes only

log()       { printf '%s\n' "$*" >&2; }
die()       { printf 'error: %s\n' "$*" >&2; exit 2; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run with sudo"; }

# need_config — stop if hb.toml doesn't parse. Acting on empty lists would quietly do nothing.
need_config() {
  "$HB_ROOT/tools/hb-config" get snapshot.dir >/dev/null 2>&1 \
    || die "cannot read config ($("$HB_ROOT/tools/hb-config" path 2>/dev/null)); try: hb config check"
}

# cfg KEY — a value from hb.toml; lists come one item per line.
cfg() { "$HB_ROOT/tools/hb-config" get "$1"; }

# keep_copy FILE — save FILE under /var/lib/hb/backup/<run>/ before changing it.
keep_copy() {
  local f="$1" d="$HB_STATE/backup/$HB_RUN"
  [ -e "$f" ] || return 0
  mkdir -p "$d$(dirname "$f")" && cp -a "$f" "$d$f"
}

confirm() {
  [ "$HB_YES" = 1 ] && return 0
  local answer
  read -r -p "$1 [y/N] " answer </dev/tty || return 1
  [[ $answer == [yY]* ]]
}

# hb_busy — run every busy.d check; print why the box is busy and return 1 if any
# says so. Callers about to disrupt work (pod restarts, reboots) ask first.
hb_busy() {
  local s out busy=0
  for s in "$HB_ROOT"/busy.d/*; do
    [ -x "$s" ] || continue
    out="$("$s" 2>&1)" || { printf 'busy: %s\n' "${out:-${s##*/}}"; busy=1; }
  done
  return $busy
}

state_word() { case $1 in 0) echo ok ;; 1) echo todo ;; *) echo FAIL ;; esac; }

# run_items VERB — VERB is check | status | plan | apply.
run_items() {
  local verb="$1" item detail rc worst=0
  local -a pending=() broken=()
  for item in "${ITEMS[@]}"; do
    detail="$(chk_"$item" 2>&1)"; rc=$?
    case "$verb" in
      status) printf '%-5s %-14s %s\n' "$(state_word $rc)" "$item" "$detail" ;;
      plan)   [ $rc -eq 1 ] && printf 'would change  %-14s %s\n' "$item" "$detail" ;;
      apply)
        if [ $rc -eq 1 ]; then
          printf '\n%s: %s\n' "$item" "$detail"
          if confirm "apply $item?"; then
            if fix_"$item"; then
              detail="$(chk_"$item" 2>&1)"; rc=$?
              printf '  now: %s  %s\n' "$(state_word $rc)" "$detail"
            else
              log "  $item: not applied"
            fi
          else
            log "  skipped"
          fi
        fi
        ;;
    esac
    [ $rc -eq 1 ] && pending+=("$item")
    [ $rc -ge 2 ] && broken+=("$item")
    [ $rc -gt $worst ] && worst=$rc
  done
  case "$verb" in
    check)
      if   [ ${#broken[@]} -gt 0 ];  then echo "fail: ${broken[*]}"
      elif [ ${#pending[@]} -gt 0 ]; then echo "warn: pending ${pending[*]}"
      else echo "ok"; fi ;;
    plan)  [ ${#pending[@]} -eq 0 ] && echo "nothing to change" ;;
    apply) echo; echo "pending: ${pending[*]:-none}   broken: ${broken[*]:-none}" ;;
  esac
  [ $worst -gt 2 ] && worst=2
  return $worst
}

# item_main "$@" — the standard verb handling for item-based tools.
item_main() {
  case "${1:-status}" in
    check|status|plan) run_items "$1" ;;
    apply) [ "${2:-}" = --yes ] && HB_YES=1; run_items apply ;;
    help|-h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0" ;;
    *) die "unknown verb '$1' (check, status, plan, apply [--yes])" ;;
  esac
}
