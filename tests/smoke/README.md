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
| Functional enroll | `playbooks/smoke.yml` + `test_artifact.py::TestFunctionalEnroll` | RSA/ECDSA-P256/Ed25519 enroll, **idempotency** (incl. curve-casing), case-insensitive key parameters (`EC`/`p256`/`ED25519` accepted, idempotent across casings and in check mode), default local-CSR key write (VC-59232), provided-CSR and PKCS#12 idempotency, invalid type/curve error, `certificate` role remote execution honours `certificate_privatekey_curve`, policy `test_mode` fail-fast, SSH modules reject NGTS |

## Regression tests (`test_artifact.py::TestRegressions`)

Four defects were confirmed in the 1.4.0 RC and fixed on branch `mi-1.4.0-regression-fixes`; E–I
were found in RC2. `TestRegressions` locks them in — a failure there means one has re-regressed.

| # | Location | Defect (now fixed) | Fix |
|---|---|---|---|
| A | `plugins/modules/venafi_policy.py` | `state: absent` without `policy_spec_path` → `KeyError('policy_spec_path')` (canonical arg is `path`; alias key absent when unsupplied) | `module.params.get(F_PS_PATH)` |
| B | `plugins/module_utils/policy_utils.py` (`_get_err_msg`) | `TypeError: 'NoneType' object is not iterable` when the platform returns `None` for a list field the local spec declares (uriProtocols/ipConstraints/domains) | iterate `(remote or [])` / `(local or [])` |
| C | `plugins/module_utils/policy_utils.py` (effective-CA compare) | effective-CA diff applied to **all** backends: a TPP folder that locks no CA (`""`) vs an omitted local CA (`DEFAULT_CA`) reported `changed=True` every run | `check_policy_specification(..., is_tpp=...)` gates the CA compare to Cloud/NGTS |
| D | `plugins/modules/venafi_certificate.py` | default local CSR with `privatekey_path` omitted → `_atomic_write(None, …)` → `TypeError` | derive the key path from `cert_path` (per the docstring) |
| E | `plugins/modules/venafi_certificate.py` | follow-up to D (1.4.0 RC2): the derived key path was also applied to a **provided CSR** (incl. the `csr_path`-exists auto-switch) → new certificate + "Private key file does not contain a valid private key" on every run | derive only for `csr_origin` local/service |
| F | `plugins/modules/venafi_certificate.py` | key path equal to `cert_path`/`chain_path` (e.g. `cert_path: x.key`) → key overwrote the certificate, every later run failed | fail before enrolling (paths compared after `os.path.realpath`, so `./`, `..` and symlinks are caught) |
| G | `plugins/modules/venafi_certificate.py` | `use_pkcs12_format` without `privatekey_path` wrote an extra `<cert>.key` next to the `.p12` | no derived path for PKCS#12 (1.3.1 behavior) |
| H | `plugins/modules/venafi_certificate.py` | encrypted key with a missing or wrong passphrase, or a non-PEM key file → `TypeError`/`ValueError` traceback | clean `fail_json` |
| I | `plugins/modules/venafi_certificate.py` | `mode` (e.g. `0644`) applied to the key/PKCS#12 → permission check failed → re-enroll + failure on every run | strip group/other bits from the key/PKCS#12 file |

E–I need a provided-CSR-capable fake backend and an issuance counter: `shims/sitecustomize.py` (test
only) makes vcert's `FakeConnection` return `cert.key=None` for a provided CSR, like the real
connectors, and logs each issuance to `$VENAFI_FAKE_ISSUE_LOG`. Tests activate it by putting
`tests/smoke/shims` first on the module's `PYTHONPATH` (the playbook uses a task `environment:`).

A/D crashed on direct module invocation; the `certificate`/`policy` roles supply the paths, so
role users were shielded. B/C affected real policy-management runs. (A was found by the smoke
tests; B–D by the parallel code review.)
