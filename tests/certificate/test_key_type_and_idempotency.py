"""
Regression tests for venafi_certificate key-type handling (bundled with the vcert 0.22.1 uptake):

  * ECDSA idempotency: an already-correct ECDSA key must NOT be judged "wrong" just because the
    requested curve casing differs from vcert's normalized value (user "P256" vs SDK "p256").
    Before the fix `_check_private_key_correct()` returned False for a matching key, so the cert
    re-enrolled on every run.

  * argspec hardening: `_get_key_type()` must fall back to the documented defaults (ECDSA -> P521,
    RSA -> 2048) instead of building KeyType(..., None) and crashing when the option is omitted.

  * Ed25519: `privatekey_type=ECDSA` + `privatekey_curve=ed25519` builds an Ed25519 KeyType
    (requires vcert>=0.22.0).

  * test_mode enrollment: with `test_mode: true` the module uses vcert's FakeConnection; a
    duplicate `read_zone_conf` in vcert 0.21.1 raised NotImplementedError and broke enrollment.
    vcert 0.22.1 fixes it, so a test_mode enroll must write the certificate and key.

  * case-insensitive key parameters: `privatekey_type` / `privatekey_curve` accept any casing
    (plus `EC`/`ECC` and `P-256`, the vcert Go SDK aliases), like 1.3.1. The RC2 argspec `choices`
    rejected the lowercase spellings (`p256`, `EC`) that were the only working ones in 1.3.1.
"""
import contextlib
import json
import os
import shutil
import tempfile
import unittest
from collections import defaultdict
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from plugins.modules import venafi_certificate
from plugins.modules.venafi_certificate import VCertificate
from vcert import ZoneConfig, CertField, KeyType

CERT_PATH = "/tmp/kt_cert.pem"
CHAIN_PATH = "/tmp/kt_chain.pem"
PRIV_PATH = "/tmp/kt_priv.pem"


class _Fail(Exception):
    pass


class FakeModule(object):
    def __init__(self, params):
        self.fail_code = None
        self.exit_code = None
        self.warn = str
        self.check_mode = False
        self.params = defaultdict(lambda: None)
        self.params.update(params)

    def exit_json(self, **kwargs):
        self.exit_code = kwargs

    def fail_json(self, **kwargs):
        self.fail_code = kwargs
        raise _Fail(kwargs.get("msg"))

    def atomic_move(self, src, dst):
        os.replace(src, dst)

    def load_file_common_arguments(self, params):
        return {}

    def set_fs_attributes_if_different(self, file_args, changed):
        return False


BASE_PARAMS = {
    "cert_path": CERT_PATH,
    "chain_path": CHAIN_PATH,
    "privatekey_path": PRIV_PATH,
    "common_name": "kt.venafi.example.com",
    "before_expired_hours": 72,
    "test_mode": True,
    "csr_origin": "local",
    "privatekey_reuse": True,
    "issuer_hint": "DEFAULT",
    "chain_option": "last",
    "zone": "",
}


def _rm(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def _write_ec_key(path, curve):
    key = ec.generate_private_key(curve)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def _build(extra=None, mock_connection=True):
    params = dict(BASE_PARAMS)
    if extra:
        params.update(extra)
    vc = VCertificate(FakeModule(params))
    if mock_connection:
        conn = mock.Mock()
        conn.read_zone_conf.return_value = ZoneConfig(
            organization=CertField(""), organizational_unit=CertField(""),
            country=CertField(""), province=CertField(""), locality=CertField(""),
            policy=None, key_type=None,
        )
        vc.connection = conn
    return vc


class TestEcdsaIdempotency(unittest.TestCase):
    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)
        _write_ec_key(PRIV_PATH, ec.SECP256R1())

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_uppercase_curve_matches_lowercase_sdk_value(self):
        # vcert reports the P-256 key as curve "p256"; the user requests "P256".
        vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": "P256"})
        self.assertTrue(
            vc._check_private_key_correct(),
            "matching ECDSA key judged wrong due to curve casing -> re-enroll churn")

    def test_hyphenated_curve_matches(self):
        vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": "P-256"})
        self.assertTrue(vc._check_private_key_correct())

    def test_wrong_curve_still_detected(self):
        # Negative control: the normalization must not mask a genuine curve mismatch.
        vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": "P384"})
        self.assertFalse(vc._check_private_key_correct())


class TestGetKeyTypeDefaults(unittest.TestCase):
    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_ecdsa_without_curve_defaults_to_p521(self):
        vc = _build({"privatekey_type": "ECDSA"})
        kt = vc._get_key_type()
        self.assertEqual(kt.key_type, KeyType.ECDSA)
        self.assertEqual(kt.option, "p521")

    def test_rsa_without_size_defaults_to_2048(self):
        vc = _build({"privatekey_type": "RSA"})
        kt = vc._get_key_type()
        self.assertEqual(kt.key_type, KeyType.RSA)
        self.assertEqual(kt.option, 2048)

    def test_ed25519_curve(self):
        vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": "ed25519"})
        kt = vc._get_key_type()
        self.assertEqual(kt.option, "ed25519")


class TestTestModeEnroll(unittest.TestCase):
    """Exercises the real vcert FakeConnection (no mock) -> guards the vcert 0.22.1
    duplicate-read_zone_conf fix and the pin floor."""

    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_test_mode_enroll_writes_cert_and_key(self):
        vc = _build(mock_connection=False)  # real FakeConnection from test_mode: true
        vc.enroll()
        self.assertTrue(os.path.exists(CERT_PATH), "test_mode enroll did not write the certificate")
        self.assertTrue(os.path.exists(PRIV_PATH), "test_mode enroll did not write the private key")


class TestKeyParamCasing(unittest.TestCase):
    """privatekey_type / privatekey_curve are matched case-insensitively and canonicalized."""

    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_ecdsa_spellings_canonicalized(self):
        for key_type, curve in (("ECDSA", "p256"), ("EC", "P256"), ("ecdsa", "P-256"), ("ECC", "p256"),
                                ("Ec", "p-256")):
            vc = _build({"privatekey_type": key_type, "privatekey_curve": curve})
            self.assertEqual((vc.privatekey_type, vc.privatekey_curve), ("ECDSA", "P256"), (key_type, curve))
            kt = vc._get_key_type()
            self.assertEqual((kt.key_type, kt.option), (KeyType.ECDSA, "p256"), (key_type, curve))

    def test_other_curves_canonicalized(self):
        for curve, canonical in (("p384", "P384"), ("P-384", "P384"), ("p521", "P521"), ("P521", "P521")):
            vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": curve})
            self.assertEqual(vc.privatekey_curve, canonical, curve)

    def test_ed25519_any_casing(self):
        for curve in ("ed25519", "ED25519", "Ed25519"):
            vc = _build({"privatekey_type": "ECDSA", "privatekey_curve": curve})
            self.assertEqual(vc.privatekey_curve, "ed25519", curve)
            self.assertEqual(vc._get_key_type().option, "ed25519", curve)

    def test_rsa_any_casing(self):
        for key_type in ("rsa", "Rsa", "RSA"):
            vc = _build({"privatekey_type": key_type, "privatekey_size": 3072})
            self.assertEqual(vc.privatekey_type, "RSA", key_type)
            kt = vc._get_key_type()
            self.assertEqual((kt.key_type, kt.option), (KeyType.RSA, 3072), key_type)

    def test_invalid_curve_fails_with_clear_message(self):
        for curve in ("P999", "secp256r1", "P-2560", "curve25519"):
            with self.assertRaises(_Fail) as ctx:
                _build({"privatekey_type": "ECDSA", "privatekey_curve": curve})
            msg = str(ctx.exception)
            self.assertIn("privatekey_curve", msg)
            self.assertIn("must be one of: P256, P384, P521, ed25519 (case-insensitive)", msg)
            self.assertIn(curve, msg)

    def test_invalid_type_fails_with_clear_message(self):
        for key_type in ("DSA", "BOGUS", "ED25519"):
            with self.assertRaises(_Fail) as ctx:
                _build({"privatekey_type": key_type})
            msg = str(ctx.exception)
            self.assertIn("privatekey_type", msg)
            self.assertIn("must be one of: ECDSA, RSA (case-insensitive)", msg)
        # a valid curve still needs a type
        with self.assertRaises(_Fail) as ctx:
            _build({"privatekey_curve": "p256"})
        self.assertIn("privatekey_type should be set", str(ctx.exception))


class TestKeyParamCasingIdempotency(unittest.TestCase):
    """An existing P-256 key matches the request whatever casing is used (no re-enroll churn)."""

    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)
        _write_ec_key(PRIV_PATH, ec.SECP256R1())

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_any_casing_matches_existing_key(self):
        for key_type, curve in (("EC", "p256"), ("ecdsa", "P256"), ("ECDSA", "P-256")):
            vc = _build({"privatekey_type": key_type, "privatekey_curve": curve})
            self.assertEqual((vc.privatekey_type, vc.privatekey_curve), ("ECDSA", "P256"), (key_type, curve))
            self.assertTrue(vc._check_private_key_correct(), (key_type, curve))
        # negative control: a genuinely different curve is still detected
        vc = _build({"privatekey_type": "EC", "privatekey_curve": "p384"})
        self.assertFalse(vc._check_private_key_correct())


class _ModuleExit(Exception):
    pass


@contextlib.contextmanager
def _module_args(args):
    """Feed module args to a real AnsibleModule (ansible-core 2.15 .. 2.21)."""
    try:
        from ansible.module_utils.testing import patch_module_args  # ansible-core >= 2.19
    except ImportError:
        patch_module_args = None
    if patch_module_args is not None:
        with patch_module_args(args):
            yield
    else:
        from ansible.module_utils import basic
        with mock.patch.object(basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": args}).encode()):
            yield


def _run_main(args):
    """Run venafi_certificate.main() through the real AnsibleModule argspec; return the result."""
    def exit_json(self, **kwargs):
        raise _ModuleExit(dict(kwargs, failed=False))

    def fail_json(self, **kwargs):
        raise _ModuleExit(dict(kwargs, failed=True))

    module_cls = venafi_certificate.AnsibleModule
    with _module_args(args), mock.patch.object(module_cls, "exit_json", exit_json), \
            mock.patch.object(module_cls, "fail_json", fail_json):
        try:
            venafi_certificate.main()
        except _ModuleExit as e:
            return e.args[0]
    raise AssertionError("main() returned without exit_json/fail_json")


def _load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


class TestKeyParamCasingMain(unittest.TestCase):
    """End to end through main(): the argspec must accept the 1.3.1 spellings (RC2 rejected them)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kt_main_")
        self.cert = os.path.join(self.tmp, "c.pem")
        self.key = os.path.join(self.tmp, "c.key")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _args(self, **kw):
        args = {"test_mode": True, "common_name": "kt-main.venafi.example.com", "cert_path": self.cert,
                "privatekey_path": self.key, "zone": ""}
        args.update(kw)
        return args

    def test_lowercase_p256_ec_enrolls_and_is_idempotent(self):
        res1 = _run_main(self._args(privatekey_type="EC", privatekey_curve="p256"))
        self.assertFalse(res1["failed"], res1)
        self.assertTrue(res1["changed"], res1)
        self.assertEqual((res1["privatekey_type"], res1["privatekey_curve"]), ("ECDSA", "P256"))
        self.assertEqual(_load_key(self.key).curve.name, "secp256r1")
        res2 = _run_main(self._args(privatekey_type="EC", privatekey_curve="p256"))
        self.assertFalse(res2["failed"], res2)
        self.assertFalse(res2["changed"], res2)
        res3 = _run_main(self._args(privatekey_type="ecdsa", privatekey_curve="P-256", _ansible_check_mode=True))
        self.assertFalse(res3["failed"], res3)
        self.assertFalse(res3["changed"], res3)

    def test_uppercase_ed25519_enrolls(self):
        res = _run_main(self._args(privatekey_type="ECDSA", privatekey_curve="ED25519"))
        self.assertFalse(res["failed"], res)
        self.assertTrue(res["changed"], res)
        self.assertIsInstance(_load_key(self.key), ed25519.Ed25519PrivateKey)

    def test_invalid_curve_fails_before_any_write(self):
        res = _run_main(self._args(privatekey_type="ECDSA", privatekey_curve="P999"))
        self.assertTrue(res["failed"], res)
        self.assertIn("privatekey_curve", res["msg"])
        self.assertIn("must be one of", res["msg"])
        self.assertIn("case-insensitive", res["msg"])  # module-level check, not the argspec choices
        self.assertFalse(os.path.exists(self.cert))
        self.assertFalse(os.path.exists(self.key))


if __name__ == "__main__":
    unittest.main()
