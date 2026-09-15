#!/usr/bin/env bash
#
# Smoke test for a BUILT venafi.machine_identity collection tarball.
#
# Stands up a throwaway virtualenv, installs the artifact's EXACT hash-pinned requirements.txt
# (vcert + cryptography) plus ansible-core, installs the collection tarball, and runs:
#   1. ansible-doc for every module           (DOCUMENTATION / doc_fragments parse)
#   2. tests/smoke/playbooks/smoke.yml         (functional enroll + idempotency + fail-fast)
#   3. tests/smoke/test_artifact.py            (packaging integrity + behaviour + regression gates)
#
# Everything runs offline (fake/test backend). No CyberArk backend or credentials needed.
#
# Usage:
#   tests/smoke/run_smoke.sh [path/to/venafi-machine_identity-X.Y.Z.tar.gz]
#
# Default tarball: ../../venafi-machine_identity-1.4.0.tar.gz relative to the repo root.
# Requires a Python 3.9-3.12 interpreter on PATH (3.9 matches the lockfile + CI most faithfully).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TARBALL="${1:-$REPO/../../venafi-machine_identity-1.4.0.tar.gz}"
WORK="${SMOKE_WORK:-/tmp/venafi-mi-smoke-run}"

filter() { grep -vE "urllib3 v2 only supports OpenSSL|NotOpenSSLWarning|warnings.warn" || true; }
say()   { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

declare -a RESULTS
record() { RESULTS+=("$1|$2"); }   # name|PASS/FAIL

if [[ ! -f "$TARBALL" ]]; then echo "ERROR: tarball not found: $TARBALL" >&2; exit 2; fi
TARBALL="$(cd "$(dirname "$TARBALL")" && pwd)/$(basename "$TARBALL")"
say "Target artifact: $TARBALL"

# ---- pick a Python 3.9-3.12 -----------------------------------------------------------------
PYBIN=""
for cand in python3.9 python3.10 python3.11 python3.12 /usr/bin/python3 python3; do
  command -v "$cand" >/dev/null 2>&1 || [[ -x "$cand" ]] || continue
  ver="$("$cand" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)" || continue
  case "$ver" in 3.9|3.10|3.11|3.12) PYBIN="$cand"; PYVER="$ver"; break;; esac
done
if [[ -z "$PYBIN" ]]; then
  echo "ERROR: need a Python 3.9-3.12 interpreter (ansible-core does not support 3.13/3.14 as controller here)" >&2
  exit 2
fi
say "Using $PYBIN (Python $PYVER)"
if [[ "$PYVER" == "3.9" ]]; then ACORE='ansible-core>=2.15,<2.16'; else ACORE='ansible-core'; fi

# ---- build env --------------------------------------------------------------------------------
rm -rf "$WORK"; mkdir -p "$WORK/artifact"
tar xzf "$TARBALL" -C "$WORK/artifact"
"$PYBIN" -m venv "$WORK/venv"
PY="$WORK/venv/bin/python"
"$PY" -m pip install -q --upgrade pip wheel 2>&1 | filter

say "Install artifact's hash-pinned requirements.txt (strict lock)"
if "$PY" -m pip install -r "$WORK/artifact/requirements.txt" 2>&1 | filter; then
  record "strict-lock-install (requirements.txt)" PASS
else
  echo "!! strict lock failed on Python $PYVER; falling back to a relaxed install so functional tests still run"
  record "strict-lock-install (requirements.txt)" FAIL
  "$PY" -m pip install -q "vcert==${SMOKE_EXPECTED_VCERT:-0.22.1}" cryptography 2>&1 | filter
fi
"$PY" -m pip install -q "$ACORE" pytest 2>&1 | filter

export ANSIBLE_COLLECTIONS_PATH="$WORK/collections"
export SMOKE_ARTIFACT_DIR="$WORK/artifact"
export SMOKE_COLLECTIONS_PATH="$WORK/collections"
GALAXY="$WORK/venv/bin/ansible-galaxy"
ADOC="$WORK/venv/bin/ansible-doc"
APLAY="$WORK/venv/bin/ansible-playbook"

say "Versions"
"$WORK/venv/bin/ansible" --version 2>&1 | filter | head -1
"$PY" -c "import vcert, importlib.metadata as m; print('vcert', m.version('vcert'))" 2>&1 | filter

# ---- 1. install the collection (verifies FILES.json checksums) --------------------------------
say "ansible-galaxy collection install (checksum verify)"
if "$GALAXY" collection install "$TARBALL" -p "$WORK/collections" --force 2>&1 | filter; then
  record "collection-install" PASS
else
  record "collection-install" FAIL
fi

# ---- 2. ansible-doc for every module ---------------------------------------------------------
say "ansible-doc for all modules"
doc_ok=PASS
for m in venafi_certificate venafi_certificate_revoke venafi_policy venafi_ssh_ca venafi_ssh_certificate; do
  if "$ADOC" "venafi.machine_identity.$m" >/dev/null 2>"$WORK/doc_$m.err"; then
    echo "  ok   $m"
  else
    echo "  FAIL $m"; cat "$WORK/doc_$m.err" | filter | head -3; doc_ok=FAIL
  fi
done
record "ansible-doc (5 modules)" "$doc_ok"

# ---- 3. functional playbook ------------------------------------------------------------------
say "ansible-playbook smoke.yml"
if "$APLAY" "$HERE/playbooks/smoke.yml" 2>&1 | filter; then
  record "playbook smoke.yml" PASS
else
  record "playbook smoke.yml" FAIL
fi

# ---- 4. pytest (packaging + behaviour + regression gates) ------------------------------------
say "pytest test_artifact.py"
if "$WORK/venv/bin/pytest" -q "$HERE/test_artifact.py" 2>&1 | filter; then
  record "pytest test_artifact.py" PASS
else
  record "pytest test_artifact.py" FAIL
fi

# ---- summary ---------------------------------------------------------------------------------
say "SUMMARY"
fail=0
for r in "${RESULTS[@]}"; do
  name="${r%%|*}"; status="${r##*|}"
  if [[ "$status" == PASS ]]; then printf '  \033[32mPASS\033[0m  %s\n' "$name"
  else printf '  \033[31mFAIL\033[0m  %s\n' "$name"; fail=1; fi
done
echo
echo "pytest includes TestRegressions (four previously-confirmed defects, now fixed);"
echo "a failure there means one of A/B/C/D has re-regressed."
echo
if [[ "$fail" == 0 ]]; then echo "RESULT: smoke suite GREEN"; else echo "RESULT: smoke suite has FAILURES (see above)"; fi
exit "$fail"
