"""
Smoke / release-gate tests for a BUILT venafi.machine_identity collection artifact.

These tests are driven by ``run_smoke.sh`` but can also be run standalone with pytest,
provided two environment variables point at a built + installed artifact:

    SMOKE_ARTIFACT_DIR       extracted tarball dir (contains MANIFEST.json / FILES.json)
    SMOKE_COLLECTIONS_PATH   ansible collections path the tarball was installed into
                             (i.e. <path>/ansible_collections/venafi/machine_identity exists)

They cover three layers:

  * Packaging integrity  -- the shipped tarball is internally consistent and free of
    developer/stray files (checksums, MANIFEST, version, dependency pin).
  * Installed behaviour   -- the INSTALLED collection's module_utils behave as the 1.4.0
    changelog claims (deprecation-warning gating, NGTS credential guards, revocation codes,
    key-type defaults), plus real test_mode enrollment through the module.
  * Regression gates      -- four confirmed defects in this artifact are encoded as
    ``xfail(strict=True)``.  They FAIL today (documenting the bug) and will turn into a hard
    failure the moment the bug is fixed, prompting removal of the marker.  See KNOWN_BUGS below.

Everything here runs offline (fake/test backend + direct object construction); no CyberArk
backend, credentials, or network are required.
"""
import hashlib
import json
import os
import stat
import subprocess
import sys

import pytest

# --------------------------------------------------------------------------------------------
# Environment / fixtures
# --------------------------------------------------------------------------------------------
ARTIFACT_DIR = os.environ.get("SMOKE_ARTIFACT_DIR")
COLLECTIONS_PATH = os.environ.get("SMOKE_COLLECTIONS_PATH")
EXPECTED_VERSION = os.environ.get("SMOKE_EXPECTED_VERSION", "1.4.0")
EXPECTED_VCERT = os.environ.get("SMOKE_EXPECTED_VCERT", "0.22.1")

MODULES = [
    "venafi_certificate",
    "venafi_certificate_revoke",
    "venafi_policy",
    "venafi_ssh_ca",
    "venafi_ssh_certificate",
]

STRAY_PATTERNS = (".claude", ".github", "CLAUDE.md", ".DS_Store", ".pytest_cache", "galaxy.yml",
                  "__pycache__", ".pyc", "vault-password", "_credentials")

needs_artifact = pytest.mark.skipif(
    not ARTIFACT_DIR or not os.path.isdir(ARTIFACT_DIR),
    reason="set SMOKE_ARTIFACT_DIR to the extracted collection tarball dir",
)
needs_installed = pytest.mark.skipif(
    not COLLECTIONS_PATH or not os.path.isdir(COLLECTIONS_PATH),
    reason="set SMOKE_COLLECTIONS_PATH to where the collection was installed",
)

if COLLECTIONS_PATH and COLLECTIONS_PATH not in sys.path:
    sys.path.insert(0, COLLECTIONS_PATH)


def _module_path(name):
    return os.path.join(
        COLLECTIONS_PATH, "ansible_collections", "venafi", "machine_identity",
        "plugins", "modules", name + ".py",
    )


def run_module(name, args, extra_env=None):
    """Invoke an installed collection module standalone and return (rc, result_dict, stderr).

    result_dict is None when the module crashed with an uncaught traceback (no JSON emitted).
    """
    env = dict(os.environ, PYTHONPATH=COLLECTIONS_PATH)
    env.update(extra_env or {})
    proc = subprocess.run(
        [sys.executable, _module_path(name)],
        input=json.dumps({"ANSIBLE_MODULE_ARGS": args}),
        text=True, capture_output=True, env=env, check=False,
    )
    result = None
    for line in reversed(proc.stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                result = json.loads(line)
                break
            except ValueError:
                continue
    return proc.returncode, result, proc.stderr


# shims/sitecustomize.py: FakeConnection returns cert.key=None for a provided CSR (like the real
# connectors) and logs every issuance to VENAFI_FAKE_ISSUE_LOG.
SHIMS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shims")


def run_certificate(tmp_path, args, check=False):
    """venafi_certificate on the fake backend with the shim; returns (result, stderr, issuances so far)."""
    log = tmp_path / "issued.log"
    args = dict({"test_mode": True, "common_name": "keypath.smoke", "zone": ""}, **args)
    if check:
        args["_ansible_check_mode"] = True
    rc, res, err = run_module("venafi_certificate", args, {
        "PYTHONPATH": os.pathsep.join([SHIMS, COLLECTIONS_PATH]), "VENAFI_FAKE_ISSUE_LOG": str(log)})
    return res, err, len(log.read_text().splitlines()) if log.exists() else 0


def write_csr(path, cn):
    """A user-provided CSR (its key stays outside the module)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])).sign(
        ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return path


class FakeModule(object):
    """Minimal AnsibleModule stand-in for exercising common_utils in-process."""

    def __init__(self, params):
        from collections import defaultdict
        self.params = defaultdict(lambda: None)
        self.params.update(params)
        self.warnings = []
        self.fail_msg = None

    def warn(self, msg):
        self.warnings.append(msg)

    def fail_json(self, **kwargs):
        self.fail_msg = kwargs.get("msg")
        raise SystemExit(self.fail_msg)


# --------------------------------------------------------------------------------------------
# Layer 1 -- packaging integrity of the shipped artifact
# --------------------------------------------------------------------------------------------
@needs_artifact
class TestPackaging:
    def _files_json(self):
        with open(os.path.join(ARTIFACT_DIR, "FILES.json")) as fh:
            return json.load(fh)

    def test_files_json_checksums_match(self):
        """Every file listed in FILES.json exists and its sha256 matches (ansible-galaxy
        verifies this on install; we assert it explicitly so a corrupt/hand-edited tarball
        is caught)."""
        mismatches = []
        for entry in self._files_json()["files"]:
            if entry.get("ftype") != "file":
                continue
            path = os.path.join(ARTIFACT_DIR, entry["name"])
            if not os.path.isfile(path):
                mismatches.append("MISSING %s" % entry["name"])
                continue
            with open(path, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            if digest != entry["chksum_sha256"]:
                mismatches.append("CHKSUM %s" % entry["name"])
        assert not mismatches, mismatches

    def test_manifest_files_json_checksum(self):
        with open(os.path.join(ARTIFACT_DIR, "MANIFEST.json")) as fh:
            manifest = json.load(fh)
        with open(os.path.join(ARTIFACT_DIR, "FILES.json"), "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
        assert manifest["file_manifest_file"]["chksum_sha256"] == actual

    def test_no_stray_developer_files(self):
        """1.4.0 changelog: excluded .claude/.github/.DS_Store/CLAUDE.md. Assert none of the
        stray/dev patterns are on disk OR listed in the manifest."""
        on_disk = []
        for root, dirs, files in os.walk(ARTIFACT_DIR):
            for name in list(dirs) + files:
                rel = os.path.relpath(os.path.join(root, name), ARTIFACT_DIR)
                if any(p in rel for p in STRAY_PATTERNS):
                    on_disk.append(rel)
        in_manifest = [e["name"] for e in self._files_json()["files"]
                       if any(p in e["name"] for p in STRAY_PATTERNS)]
        assert not on_disk, "stray files on disk: %s" % on_disk
        assert not in_manifest, "stray files in FILES.json: %s" % in_manifest

    def test_version_matches(self):
        with open(os.path.join(ARTIFACT_DIR, "MANIFEST.json")) as fh:
            manifest = json.load(fh)
        info = manifest["collection_info"]
        assert info["version"] == EXPECTED_VERSION
        assert info["namespace"] == "venafi"
        assert info["name"] == "machine_identity"

    def test_requirements_pin_and_hashes(self):
        """requirements.txt must pin the expected vcert and be a hash lock (every == line has
        an accompanying --hash)."""
        with open(os.path.join(ARTIFACT_DIR, "requirements.txt")) as fh:
            txt = fh.read()
        assert "vcert==%s" % EXPECTED_VCERT in txt
        assert "--hash=sha256:" in txt
        # every pinned top-level requirement line should carry at least one hash somewhere after
        assert txt.count("--hash=sha256:") >= 20  # full transitive lock, not a stub

    def test_requirements_in_floor(self):
        with open(os.path.join(ARTIFACT_DIR, "requirements.in")) as fh:
            assert "vcert>=" in fh.read()

    def test_runtime_requires_ansible(self):
        with open(os.path.join(ARTIFACT_DIR, "meta", "runtime.yml")) as fh:
            assert "requires_ansible" in fh.read()


# --------------------------------------------------------------------------------------------
# Layer 2 -- behaviour of the INSTALLED collection (1.4.0 changelog claims)
# --------------------------------------------------------------------------------------------
@needs_installed
class TestInstalledBehaviour:
    def _common_utils(self):
        from ansible_collections.venafi.machine_identity.plugins.module_utils import common_utils
        return common_utils

    def test_module_utils_import(self):
        cu = self._common_utils()
        assert cu.HAS_VCERT is True

    def test_deprecation_warning_silent_for_token_only(self):
        """1.4.0: 'Stopped emitting the user/password deprecation warning' on token-only runs."""
        cu = self._common_utils()
        m = FakeModule({"test_mode": False, "token": "abc"})
        try:
            cu.get_venafi_connection(m)
        except Exception:
            pass  # connection construction may raise on the fake token; we only assert warnings
        assert m.warnings == [], m.warnings

    def test_deprecation_warning_fires_for_user_password(self):
        cu = self._common_utils()
        m = FakeModule({"test_mode": False, "url": "https://x", "user": "u", "password": "p"})
        try:
            cu.get_venafi_connection(m)
        except Exception:
            pass
        assert any("deprecated" in w for w in m.warnings), m.warnings

    def test_ngts_partial_credentials_guard(self):
        cu = self._common_utils()
        m = FakeModule({"test_mode": False, "client_id": "c"})  # secret missing
        with pytest.raises(SystemExit):
            cu.get_venafi_connection(m)
        assert "client_secret" in (m.fail_msg or "")

    def test_ngts_requires_tsg_or_scope(self):
        cu = self._common_utils()
        m = FakeModule({"test_mode": False, "client_id": "c", "client_secret": "s"})
        with pytest.raises(SystemExit):
            cu.get_venafi_connection(m)
        assert "tsg_id" in (m.fail_msg or "") or "scope" in (m.fail_msg or "")

    def test_revocation_reason_codes(self):
        """Reason strings/codes match the Go vcert CLI vocabulary."""
        cu = self._common_utils()
        assert cu.get_revocation_reason("key-compromise") == 1
        assert cu.get_revocation_reason("cessation-of-operation") == 5
        assert cu.get_revocation_reason(None) == 0
        with pytest.raises(cu.VenafiAnsibleError):
            cu.get_revocation_reason("bogus")

    def test_key_type_defaults(self):
        """1.4.0: privatekey_type=ECDSA -> P521, RSA -> 2048 fallbacks; ed25519 accepted."""
        from ansible_collections.venafi.machine_identity.plugins.modules.venafi_certificate \
            import VCertificate
        from vcert import KeyType

        def kt(params):
            base = {"test_mode": True, "common_name": "x", "cert_path": "/tmp/x",
                    "csr_origin": "local", "issuer_hint": "DEFAULT", "chain_option": "last",
                    "before_expired_hours": 72, "privatekey_reuse": True, "zone": ""}
            base.update(params)
            return VCertificate(FakeModule(base))._get_key_type()

        assert kt({"privatekey_type": "ECDSA"}).option == "p521"
        assert kt({"privatekey_type": "RSA"}).option == 2048
        assert kt({"privatekey_type": "ECDSA", "privatekey_curve": "ed25519"}).option == "ed25519"
        assert kt({"privatekey_type": "ECDSA"}).key_type == KeyType.ECDSA


# --------------------------------------------------------------------------------------------
# Layer 3 -- functional enrollment through the module (fake backend)
# --------------------------------------------------------------------------------------------
@needs_installed
class TestFunctionalEnroll:
    def _classify(self, key_path):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
        with open(key_path, "rb") as fh:
            key = load_pem_private_key(fh.read(), password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            return "RSA:%d" % key.key_size
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return "EC:%s" % key.curve.name
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return "Ed25519"
        return type(key).__name__

    def test_default_local_csr_writes_rsa_key(self, tmp_path):
        """VC-59232 #2: a default local CSR (no privatekey_type) writes the generated key.
        Uses an explicit privatekey_path (the supported path; see xfail for the omitted case)."""
        cert = tmp_path / "def.crt"
        key = tmp_path / "def.key"
        rc, res, err = run_module("venafi_certificate", {
            "test_mode": True, "common_name": "def.smoke", "cert_path": str(cert),
            "privatekey_path": str(key), "zone": "",
        })
        assert res is not None and not res.get("failed"), (err, res)
        assert res.get("changed") is True
        assert key.exists() and self._classify(str(key)) == "RSA:2048"

    def test_ed25519_enroll(self, tmp_path):
        cert = tmp_path / "ed.crt"
        key = tmp_path / "ed.key"
        rc, res, err = run_module("venafi_certificate", {
            "test_mode": True, "common_name": "ed.smoke", "cert_path": str(cert),
            "privatekey_path": str(key), "privatekey_type": "ECDSA",
            "privatekey_curve": "ed25519", "zone": "",
        })
        assert res is not None and not res.get("failed"), (err, res)
        assert self._classify(str(key)) == "Ed25519"

    def test_ecdsa_p256_enroll_and_idempotent(self, tmp_path):
        cert = tmp_path / "ec.crt"
        key = tmp_path / "ec.key"
        args = {"test_mode": True, "common_name": "ec.smoke", "cert_path": str(cert),
                "privatekey_path": str(key), "privatekey_type": "ECDSA",
                "privatekey_curve": "P256", "zone": ""}
        rc, res1, err1 = run_module("venafi_certificate", args)
        assert res1 is not None and res1.get("changed") is True, (err1, res1)
        assert self._classify(str(key)) == "EC:secp256r1"
        # second run: curve casing must not force a re-enroll (ECDSA idempotency fix)
        rc, res2, err2 = run_module("venafi_certificate", args)
        assert res2 is not None and res2.get("changed") is False, (err2, res2)

    def test_invalid_privatekey_type_clean_error(self, tmp_path):
        rc, res, err = run_module("venafi_certificate", {
            "test_mode": True, "common_name": "bad.smoke", "cert_path": str(tmp_path / "b.crt"),
            "privatekey_type": "BOGUS", "zone": "",
        })
        assert "Traceback" not in err, err
        assert res is not None and res.get("failed") is True
        assert "must be one of" in res.get("msg", "")

    def test_lowercase_curve_and_ec_type_accepted_idempotent(self, tmp_path):
        """M14: the 1.3.1 spellings (type EC, curve p256) are accepted and stay idempotent,
        also when the casing changes between runs and in check mode."""
        cert = tmp_path / "lc.crt"
        key = tmp_path / "lc.key"
        args = {"test_mode": True, "common_name": "lc.smoke", "cert_path": str(cert),
                "privatekey_path": str(key), "privatekey_type": "EC",
                "privatekey_curve": "p256", "zone": ""}
        rc, res1, err1 = run_module("venafi_certificate", args)
        assert res1 is not None and res1.get("changed") is True, (err1, res1)
        assert res1.get("privatekey_curve") == "P256" and res1.get("privatekey_type") == "ECDSA"
        assert self._classify(str(key)) == "EC:secp256r1"
        rc, res2, err2 = run_module("venafi_certificate", args)
        assert res2 is not None and res2.get("changed") is False, (err2, res2)
        args.update({"privatekey_type": "ecdsa", "privatekey_curve": "P-256", "_ansible_check_mode": True})
        rc, res3, err3 = run_module("venafi_certificate", args)
        assert res3 is not None and not res3.get("failed") and res3.get("changed") is False, (err3, res3)

    def test_uppercase_ed25519_accepted(self, tmp_path):
        key = tmp_path / "edu.key"
        rc, res, err = run_module("venafi_certificate", {
            "test_mode": True, "common_name": "edu.smoke", "cert_path": str(tmp_path / "edu.crt"),
            "privatekey_path": str(key), "privatekey_type": "ECDSA",
            "privatekey_curve": "ED25519", "zone": "",
        })
        assert res is not None and res.get("changed") is True, (err, res)
        assert self._classify(str(key)) == "Ed25519"

    def test_invalid_privatekey_curve_clean_error(self, tmp_path):
        cert = tmp_path / "bc.crt"
        key = tmp_path / "bc.key"
        rc, res, err = run_module("venafi_certificate", {
            "test_mode": True, "common_name": "bc.smoke", "cert_path": str(cert),
            "privatekey_path": str(key), "privatekey_type": "ECDSA",
            "privatekey_curve": "P999", "zone": "",
        })
        assert "Traceback" not in err, err
        assert res is not None and res.get("failed") is True, (err, res)
        assert "privatekey_curve" in res.get("msg", "") and "must be one of" in res.get("msg", "")
        assert "case-insensitive" in res.get("msg", "")  # module-level check, not argspec choices
        assert not cert.exists() and not key.exists()  # failed before any request / write

    def test_policy_test_mode_fails_fast(self, tmp_path):
        spec = tmp_path / "p.json"
        spec.write_text("{}")
        rc, res, err = run_module("venafi_policy", {
            "test_mode": True, "zone": "z", "state": "present", "policy_spec_path": str(spec),
        })
        assert "Traceback" not in err, err
        assert res is not None and res.get("failed") is True
        assert "test_mode" in res.get("msg", "")

    def test_ssh_modules_reject_ngts(self, tmp_path):
        rc, res, err = run_module("venafi_ssh_ca", {
            "client_id": "c", "client_secret": "s", "tsg_id": "1",
            "ca_template": "t", "public_key_path": str(tmp_path / "ca.pub"),
        })
        assert res is not None and res.get("failed") is True
        assert "NGTS" in res.get("msg", "") and "SSH CA" in res.get("msg", "")


# --------------------------------------------------------------------------------------------
# Layer 4 -- regression tests for four defects confirmed in the 1.4.0 RC and fixed on
# branch mi-1.4.0-regression-fixes. These MUST stay green; a failure here is a re-regression.
#   A  venafi_policy.py       state=absent without policy_spec_path used to KeyError
#   B  policy_utils.py        _get_err_msg used to TypeError on a None remote list (uri/ip/domains)
#   C  policy_utils.py        effective-CA compare used to churn on TPP folders that lock no CA
#   D  venafi_certificate.py  default local CSR without privatekey_path used to TypeError
# Private-key path follow-ups to D (found in 1.4.0 RC2; E-I use shims/sitecustomize.py):
#   E  provided CSR without privatekey_path re-enrolled + failed validation on every run
#   F  key path == cert/chain path destroyed the certificate (now fails before enrolling)
#   G  PKCS#12 without privatekey_path wrote an extra <cert>.key next to the .p12
#   H  encrypted/unreadable key crashed with a TypeError/ValueError traceback
#   I  mode (e.g. 0644) left group/other bits on the key -> re-enroll + failure on every run
# --------------------------------------------------------------------------------------------
@needs_installed
class TestRegressions:
    def test_a_policy_absent_without_path_no_crash(self):
        rc, res, err = run_module("venafi_policy", {"test_mode": True, "zone": "z", "state": "absent"})
        assert "Traceback" not in err and "KeyError" not in err, err
        assert res is not None and res.get("failed") is True, (err, res)
        assert "test_mode" in res.get("msg", "")  # reached the fail-fast guard, not a crash

    def test_b_uri_drift_remote_none_reports_change(self):
        from vcert.policy.policy_spec import PolicySpecification, Policy, SubjectAltNames
        from ansible_collections.venafi.machine_identity.plugins.module_utils.policy_utils \
            import check_policy_specification
        local = PolicySpecification(policy=Policy(
            subject_alt_names=SubjectAltNames(uri_allowed=True, uri_protocols=["https"])))
        remote = PolicySpecification(policy=Policy(
            subject_alt_names=SubjectAltNames(uri_allowed=True, uri_protocols=None)))
        changed = check_policy_specification(local, remote, ignore_owners_users=False)[0]
        assert changed is True  # reports drift instead of raising TypeError

    def test_c_tpp_ca_backend_aware(self):
        from vcert.policy.policy_spec import PolicySpecification, Policy, DEFAULT_CA
        from ansible_collections.venafi.machine_identity.plugins.module_utils.policy_utils \
            import check_policy_specification

        def mkpol(ca):
            p = Policy(domains=["example.com"], max_valid_days=90, wildcard_allowed=True)
            p.certificate_authority = ca
            return p

        omit = PolicySpecification(policy=mkpol(DEFAULT_CA))  # local file omits CA -> DEFAULT_CA
        tpp_no_ca = PolicySpecification(policy=mkpol(""))      # TPP folder with no CA locked
        # TPP: an omitted/built-in local CA must NOT churn against a folder that locks no CA
        assert check_policy_specification(omit, tpp_no_ca, is_tpp=True)[0] is False
        # Cloud/NGTS: the effective-CA reset is still reported (converges after one apply)
        assert check_policy_specification(omit, tpp_no_ca, is_tpp=False)[0] is True
        # TPP: an explicitly-set real CA is still diffed
        real = PolicySpecification(policy=mkpol("\\VED\\Policy\\RealCA"))
        assert check_policy_specification(real, tpp_no_ca, is_tpp=True)[0] is True
        assert check_policy_specification(real, PolicySpecification(policy=mkpol("\\VED\\Policy\\RealCA")),
                                          is_tpp=True)[0] is False

    def test_d_default_local_csr_no_privatekey_path(self, tmp_path):
        cert = tmp_path / "nopk.crt"
        rc, res, err = run_module("venafi_certificate", {
            "test_mode": True, "common_name": "nopk.smoke", "cert_path": str(cert), "zone": "",
        })
        assert "Traceback" not in err, err
        assert res is not None and not res.get("failed"), (err, res)
        # key written to the derived path (cert base + .key), per the documented behavior
        assert res.get("privatekey_filename") == str(tmp_path / "nopk.key")
        assert (tmp_path / "nopk.key").exists()

    @pytest.mark.parametrize("csr_origin", ["provided", None])  # None: auto-switch, csr_path exists
    def test_e_provided_csr_without_privatekey_path_is_idempotent(self, tmp_path, csr_origin):
        args = {"cert_path": str(tmp_path / "c.crt"),
                "csr_path": str(write_csr(tmp_path / "csr.pem", "keypath.smoke"))}
        if csr_origin:
            args["csr_origin"] = csr_origin
        res, err, issued = run_certificate(tmp_path, args)
        assert res is not None and res.get("changed") is True and not res.get("failed"), (err, res)
        assert not res.get("privatekey_filename")
        for extra, check in (({}, False), ({}, True), ({"renew": False}, False)):
            res, err, issued = run_certificate(tmp_path, dict(args, **extra), check=check)
            assert res is not None and res.get("changed") is False and not res.get("failed"), (extra, check, err, res)
        assert issued == 1  # one enrollment, not one per run
        assert sorted(p.name for p in tmp_path.iterdir()) == ["c.crt", "csr.pem", "issued.log"]

    @pytest.mark.parametrize("paths", [
        {"cert_path": "c.key"},                              # derived key path == cert_path
        {"cert_path": "c.crt", "chain_path": "c.key"},       # derived key path == chain_path
        {"cert_path": "c.crt", "privatekey_path": "c.crt"},  # explicit key path == cert_path
        {"cert_path": "c.crt", "chain_path": "./c.key"},     # same file, different spelling
    ])
    def test_f_key_path_collision_fails_before_enrolling(self, tmp_path, paths):
        args = dict((k, os.path.join(str(tmp_path), v)) for k, v in paths.items())
        for check in (True, False):
            res, err, issued = run_certificate(tmp_path, args, check=check)
            assert "Traceback" not in err, err
            assert res is not None and res.get("failed") is True, (check, err, res)
            assert "same file as the certificate or chain" in res.get("msg", "")
        assert issued == 0 and not list(tmp_path.iterdir())

    def test_g_pkcs12_without_privatekey_path_writes_only_p12(self, tmp_path):
        args = {"cert_path": str(tmp_path / "c.p12"), "use_pkcs12_format": True}
        res, err, issued = run_certificate(tmp_path, args)
        assert res is not None and res.get("changed") is True and not res.get("failed"), (err, res)
        res, err, issued = run_certificate(tmp_path, args)
        assert res is not None and res.get("changed") is False and not res.get("failed"), (err, res)
        assert issued == 1
        assert sorted(p.name for p in tmp_path.iterdir()) == ["c.p12", "issued.log"]  # no c.key
        assert stat.S_IMODE((tmp_path / "c.p12").stat().st_mode) == 0o600

    def test_h_unreadable_private_key_fails_cleanly(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = tmp_path / "c.key"  # encrypted key at the derived path, no privatekey_passphrase given
        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"secret"))
        key.write_bytes(pem)
        res, err, issued = run_certificate(tmp_path, {"cert_path": str(tmp_path / "c.crt")})
        assert "Traceback" not in err, err
        assert res is not None and res.get("failed") is True, (err, res)
        assert "Failed to load private key file" in res.get("msg", "")
        assert issued == 0 and key.read_bytes() == pem  # not re-enrolled, key not overwritten

    def test_i_mode_0644_keeps_private_key_0600_and_is_idempotent(self, tmp_path):
        args = {"cert_path": str(tmp_path / "c.crt"), "mode": "0644"}
        res, err, issued = run_certificate(tmp_path, args)
        assert res is not None and res.get("changed") is True and not res.get("failed"), (err, res)
        res, err, issued = run_certificate(tmp_path, args)
        assert res is not None and res.get("changed") is False and not res.get("failed"), (err, res)
        assert issued == 1
        assert stat.S_IMODE((tmp_path / "c.key").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "c.crt").stat().st_mode) == 0o644


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
