#!/usr/bin/env bash
# tests/al2023.sh — hb on Amazon Linux 2023's userland, in the official container image:
# its Python 3.9 next to python3.13, dnf 4, rpm. Runs `hb check` as root with no hb.toml
# (defaults manage nothing), installs restic as hb install does and backs a file up with it
# (needs GitHub; skipped when out of reach), then the test suite as a normal user under python3.13.
# No systemd, sshd or kernel in a container: those parts only the real box tests.
#
#   tests/al2023.sh            docker (or podman), from the checkout
# Exit 0 only when the tests pass and no check broke. Some checks fail by design in an
# empty container (install: nothing installed; health: no kernel package), so hb check's own
# exit status doesn't count; a check that broke (a crash, see hb) does.
# Only git's files go in (never hb.toml or local/). Leaves one local image, hb-al2023-test.
set -euo pipefail
cd "$(dirname "$0")/.."
run=$(command -v docker || command -v podman) || { echo "needs docker or podman" >&2; exit 2; }
"$run" build -q -t hb-al2023-test - >/dev/null <<'EOF'
FROM amazonlinux:2023
RUN dnf install -y -q python3.13 dnf-utils procps-ng util-linux findutils iproute openssl hostname \
      diffutils which tar gzip shadow-utils openssh-server git make && dnf clean all
EOF
git ls-files -co --exclude-standard -z | tar --null -T - -cz |
"$run" run --rm -i hb-al2023-test bash -c '
  set -u
  bad=0
  useradd -m tester && mkdir /home/tester/hb && tar xz -C /home/tester/hb && chown -R tester: /home/tester/hb
  cd /home/tester/hb
  echo "== $(cat /etc/amazon-linux-release); /usr/bin/python3 is $(python3 -V)"
  echo "== hb check (root, no hb.toml)"
  ./hb check > /tmp/check 2>&1
  cat /tmp/check
  if grep -q "the check broke" /tmp/check || ! tail -1 /tmp/check | grep -qE "^[0-9]+ ok, [0-9]+ warn, [0-9]+ fail"; then
    echo "FAILED: a check broke, or hb check did not finish"; bad=1
  fi
  echo "== restic, as hb install puts it there (the release from GitHub, SHA-256 checked), and a backup with it"
  case "$(uname -m)" in   # restic 0.19.1, from its SHA256SUMS (signature checked on 9 Nov 2026)
    x86_64) sha=f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c ;;
    aarch64) sha=a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465 ;;
  esac
  if ! curl -fsSI -o /dev/null --max-time 20 https://github.com; then
    echo "skipped: GitHub is out of reach"
  else
    printf "[backup]\nrepo = \"local:/var/tmp/repo\"\nrestic_version = \"0.19.1\"\nrestic_sha256 = \"%s\"\n" "$sha" > /tmp/e2e.toml
    sed -e "s|^source .*|source $PWD/lib/hb.sh|" -e "/^need_root$/d" -e "/^need_config$/d" -e "/^item_main/d" \
      tools/hb-install > /tmp/install-functions
    export HB_CONFIG=/tmp/e2e.toml
    if bash -c "source /tmp/install-functions; fix_restic && chk_restic" \
       && ./hb backup init > /dev/null && ./hb backup restic backup -q --host al2023 --tag hb /etc/os-release \
       && ./hb backup status; then
      echo "restic e2e ok"
    else
      echo "FAILED: restic e2e"; bad=1
    fi
    unset HB_CONFIG
  fi
  echo "== the tests (python3.13, as a normal user)"
  runuser -u tester -- python3.13 -B -m unittest discover -s tests > /tmp/tests 2>&1
  rc=$?
  grep -E "^(Ran|OK|FAILED|FAIL:|ERROR:)" /tmp/tests || tail -20 /tmp/tests
  [ "$rc" -eq 0 ] || bad=1
  exit "$bad"'
