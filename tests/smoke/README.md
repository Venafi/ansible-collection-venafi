# Smoke tests — `venafi.machine_identity` built artifact

Release-gate smoke tests for a **built collection tarball** (e.g.
`venafi-machine_identity-1.4.0.tar.gz`). They stand up a throwaway virtualenv, install the
artifact's *exact* hash-pinned `requirements.txt`, install the collection, and exercise it
end-to-end on the **fake/test backend** — no CyberArk backend, credentials, or network.

## Run

```sh
tests/smoke/run_smoke.sh [path/to/venafi-machine_identity-X.Y.Z.tar.gz]
# default tarball: ../../venafi-machine_identity-1.4.0.tar.gz (workspace root)
```

Requires a **Python 3.9–3.12** interpreter on `PATH` (3.9 matches the lockfile + CI most
faithfully; ansible-core does not support 3.13/3.14 as a controller here). Docker is not needed.

Run the pytest layer alone against an already-installed collection:

```sh
SMOKE_ARTIFACT_DIR=<extracted-tarball-dir> \
SMOKE_COLLECTIONS_PATH=<ansible-collections-path> \
pytest tests/smoke/test_artifact.py -v
```

## What it covers

| Layer | File | Checks |
|---|---|---|
| Packaging integrity | `test_artifact.py::TestPackaging` | FILES.json sha256 all match; MANIFEST↔FILES.json checksum; **no stray dev files** (`.claude`/`.github`/`CLAUDE.md`/`.DS_Store`/`galaxy.yml`/`__pycache__`); version; `vcert==` pin + hash lock; `requires_ansible` |
| Install / interface | `run_smoke.sh` | `ansible-galaxy collection install` (checksum verify), `ansible-doc` for all 5 modules |
| Installed behaviour | `test_artifact.py::TestInstalledBehaviour` | deprecation-warning gating (token-only silent, user/password warns), NGTS credential guards, revocation reason codes, key-type defaults (ECDSA→P521, RSA→2048, ed25519) |
| Functional enroll | `playbooks/smoke.yml` + `test_artifact.py::TestFunctionalEnroll` | RSA/ECDSA-P256/Ed25519 enroll, **idempotency** (incl. curve-casing), default local-CSR key write (VC-59232), invalid-choice error, policy `test_mode` fail-fast, SSH modules reject NGTS |

## Regression tests (`test_artifact.py::TestRegressions`)

Four defects were confirmed in the 1.4.0 RC and fixed on branch `mi-1.4.0-regression-fixes`.
`TestRegressions` locks them in — a failure there means one has re-regressed.

| # | Location | Defect (now fixed) | Fix |
|---|---|---|---|
| A | `plugins/modules/venafi_policy.py` | `state: absent` without `policy_spec_path` → `KeyError('policy_spec_path')` (canonical arg is `path`; alias key absent when unsupplied) | `module.params.get(F_PS_PATH)` |
| B | `plugins/module_utils/policy_utils.py` (`_get_err_msg`) | `TypeError: 'NoneType' object is not iterable` when the platform returns `None` for a list field the local spec declares (uriProtocols/ipConstraints/domains) | iterate `(remote or [])` / `(local or [])` |
| C | `plugins/module_utils/policy_utils.py` (effective-CA compare) | effective-CA diff applied to **all** backends: a TPP folder that locks no CA (`""`) vs an omitted local CA (`DEFAULT_CA`) reported `changed=True` every run | `check_policy_specification(..., is_tpp=...)` gates the CA compare to Cloud/NGTS |
| D | `plugins/modules/venafi_certificate.py` | default local CSR with `privatekey_path` omitted → `_atomic_write(None, …)` → `TypeError` | derive the key path from `cert_path` (per the docstring) |

A/D crashed on direct module invocation; the `certificate`/`policy` roles supply the paths, so
role users were shielded. B/C affected real policy-management runs. (A was found by the smoke
tests; B–D by the parallel code review.)
