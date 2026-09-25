"""
Private-key path handling in venafi_certificate (follow-up to the VC-59232 key-path derivation).

When privatekey_path is omitted, the key path is derived from cert_path ("placed near certificate
with key suffix"), but only when the module generates the key (csr_origin local/service):

  * provided CSR (explicit, or auto-switched because csr_path exists): no derived path. The
    backend returns no key, so a derived path was never written and every run re-enrolled and
    then failed validation ("Private key file does not contain a valid private key").
  * PKCS#12: no derived path. The key is stored inside the .p12 file; no extra <cert>.key copy.
  * a key path equal to the certificate/chain/PKCS#12 file fails before enrolling (the key write
    would overwrite the certificate).
  * an unreadable key (encrypted without / with a wrong passphrase, not a PEM key) fails with a
    clear message instead of a TypeError/ValueError traceback.
  * the key / PKCS#12 file never keeps group/other permissions from `mode`, which
    _check_file_permissions() rejects (re-enroll on every run).

The connection is mocked; certificates are real so check() can be exercised on converged state.
"""
import datetime
import os
import shutil
import stat
import tempfile
import unittest
from collections import defaultdict
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from plugins.modules.venafi_certificate import VCertificate
from vcert import ZoneConfig, CertField

CN = "keypath.venafi.example.com"


class _Fail(Exception):
    pass


class FakeModule(object):
    """Minimal AnsibleModule stand-in, including the file helpers enroll() uses (mode is applied)."""

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
        return {"mode": params.get("mode")}

    def set_fs_attributes_if_different(self, file_args, changed):
        if file_args.get("mode") is None:
            return False
        mode = int(file_args["mode"], 8)
        if stat.S_IMODE(os.stat(file_args["path"]).st_mode) == mode:
            return False
        os.chmod(file_args["path"], mode)
        return True


def _new_key():
    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key, passphrase=None):
    enc = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase \
        else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode()


class _Issued(object):
    """What connection.retrieve_cert() returns: a real certificate for `key`.

    with_key=False mimics the real connectors for a provided CSR (cert.key is None)."""

    def __init__(self, key=None, with_key=True):
        self._key = key or _new_key()
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)])
        self._crt = x509.CertificateBuilder().subject_name(name).issuer_name(name) \
            .public_key(self._key.public_key()).serial_number(x509.random_serial_number()) \
            .not_valid_before(now - datetime.timedelta(days=1)) \
            .not_valid_after(now + datetime.timedelta(days=30)) \
            .sign(self._key, hashes.SHA256())
        self.cert = self._crt.public_bytes(serialization.Encoding.PEM).decode()
        self.chain = []
        self.full_chain = self.cert
        self.key = _key_pem(self._key) if with_key else None

    def as_pkcs12(self, passphrase=None):
        return pkcs12.serialize_key_and_certificates(
            b"keypath", self._key, self._crt, None, serialization.NoEncryption())


def _zone_config():
    return ZoneConfig(
        organization=CertField(""), organizational_unit=CertField(""),
        country=CertField(""), province=CertField(""), locality=CertField(""),
        policy=None, key_type=None,
    )


class TestKeyPathDerivation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.cert = self._p("c.crt")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _p(self, name):
        return os.path.join(self.d, name)

    def _write(self, name, content, mode=0o600):
        path = self._p(name)
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, mode)
        return path

    def _build(self, issued=None, **extra):
        params = {
            "cert_path": self.cert,
            "common_name": CN,
            "before_expired_hours": 72,
            "test_mode": True,          # FakeConnection at construction; replaced by a mock below
            "csr_origin": "local",
            "privatekey_reuse": True,
            "issuer_hint": "DEFAULT",
            "chain_option": "last",
            "zone": "",
        }
        params.update(extra)
        vc = VCertificate(FakeModule(params))
        conn = mock.Mock()
        conn.read_zone_conf.return_value = _zone_config()
        conn.request_cert.return_value = True
        conn.retrieve_cert.return_value = issued or _Issued()
        vc.connection = conn
        return vc

    def _provided_csr(self):
        key = _new_key()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)])).sign(key, hashes.SHA256())
        return key, self._write("csr.pem", csr.public_bytes(serialization.Encoding.PEM).decode(), 0o644)

    def _files(self):
        return sorted(f for f in os.listdir(self.d) if f not in ("csr.pem", "csr.key"))

    # --- provided CSR: no derived key path, 1.3.1 behavior ------------------------------------
    def _assert_provided_converges(self, **extra):
        key, csr = self._provided_csr()
        vc = self._build(issued=_Issued(key, with_key=False), csr_path=csr, **extra)
        self.assertEqual(vc.csr_origin, "provided")
        self.assertFalse(vc.privatekey_filename)
        self.assertTrue(vc.check(validate=False)["changed"])  # no certificate yet
        vc.enroll()
        self.assertEqual(self._files(), ["c.crt"])  # no key written, nothing else touched
        vc.validate()  # raises _Fail on RC2: derived c.key never exists -> "not a valid private key"
        # second run on the converged certificate: nothing to do
        again = self._build(csr_path=csr, **extra)
        self.assertFalse(again.check(validate=False)["changed"], again.changed_message)

    def test_provided_csr_explicit_no_privatekey_path(self):
        self._assert_provided_converges(csr_origin="provided")

    def test_provided_csr_auto_switch_no_privatekey_path(self):
        # csr_origin left at "local": an existing csr_path switches to a provided CSR
        self._assert_provided_converges()

    def test_provided_csr_empty_privatekey_path(self):
        self._assert_provided_converges(csr_origin="provided", privatekey_path="")

    def test_provided_csr_ignores_unrelated_encrypted_key_at_derived_path(self):
        # an encrypted key that happens to live at <cert>.key used to raise a TypeError traceback
        other = _key_pem(_new_key(), "other")
        enc = self._write("c.key", other)
        key, csr = self._provided_csr()
        self._write("c.crt", _Issued(key).cert, 0o644)
        vc = self._build(csr_path=csr)
        self.assertFalse(vc.check(validate=False)["changed"], vc.changed_message)
        self.assertEqual(open(enc).read(), other)

    def test_provided_csr_explicit_privatekey_path_still_checked(self):
        key, csr = self._provided_csr()
        key_path = self._write("csr.key", _key_pem(key))
        self._write("c.crt", _Issued(key).cert, 0o644)
        vc = self._build(csr_path=csr, privatekey_path=key_path)
        self.assertEqual(vc.privatekey_filename, key_path)
        self.assertFalse(vc.check(validate=False)["changed"], vc.changed_message)
        # a different key at the explicit path is still reported as a mismatch
        self._write("csr.key", _key_pem(_new_key()))
        self.assertTrue(self._build(csr_path=csr, privatekey_path=key_path).check(validate=False)["changed"])

    # --- local / service CSR keep the derived path -------------------------------------------
    def test_local_and_service_csr_derive_key_path(self):
        self.assertEqual(self._build().privatekey_filename, self._p("c.key"))
        vc = self._build(csr_origin="service", privatekey_passphrase="pass")
        self.assertEqual(vc.privatekey_filename, self._p("c.key"))

    def test_local_csr_derived_key_written_and_idempotent(self):
        vc = self._build()
        vc.enroll()
        self.assertEqual(self._files(), ["c.crt", "c.key"])
        self.assertEqual(stat.S_IMODE(os.stat(self._p("c.key")).st_mode), 0o600)
        vc.validate()
        self.assertFalse(self._build().check(validate=False)["changed"])

    # --- PKCS#12: key only inside the .p12 file (1.3.1 behavior) ------------------------------
    def test_pkcs12_without_privatekey_path_writes_only_p12(self):
        self.cert = self._p("c.p12")
        vc = self._build(use_pkcs12_format=True)
        self.assertIsNone(vc.privatekey_filename)
        with mock.patch.object(vc, "_atomic_write", wraps=vc._atomic_write) as aw:
            vc.enroll()
        self.assertNotIn(None, [c[0][0] for c in aw.call_args_list])
        self.assertEqual(self._files(), ["c.p12"])
        self.assertEqual(stat.S_IMODE(os.stat(self.cert).st_mode), 0o600)
        vc.validate()
        self.assertFalse(self._build(use_pkcs12_format=True).check(validate=False)["changed"])

    def test_pkcs12_with_privatekey_path_still_writes_key(self):
        self.cert = self._p("c.p12")
        key_path = self._p("k.pem")
        vc = self._build(use_pkcs12_format=True, privatekey_path=key_path)
        vc.enroll()
        self.assertEqual(self._files(), ["c.p12", "k.pem"])

    # --- key path colliding with the certificate / chain --------------------------------------
    def _assert_collision(self, **extra):
        with self.assertRaises(_Fail) as ctx:
            self._build(**extra)
        self.assertIn("same file as the certificate or chain", str(ctx.exception))

    def test_collision_cert_path_ends_in_key(self):
        self.cert = self._p("c.key")
        self._assert_collision()

    def test_collision_chain_path_is_derived_key_path(self):
        self._assert_collision(chain_path=self._p("c.key"))

    def test_collision_explicit_privatekey_path(self):
        self._assert_collision(privatekey_path=self.cert)
        self._assert_collision(privatekey_path=self._p("ch.pem"), chain_path=self._p("ch.pem"))

    def test_collision_explicit_privatekey_path_is_pkcs12_file(self):
        self._assert_collision(use_pkcs12_format=True, privatekey_path=self._p("c.p12"))

    def test_collision_detected_through_path_spelling(self):
        # "./", ".." or a symlink must not hide the shared file (the chain would silently hold the key)
        self._assert_collision(chain_path=os.path.join(self.d, ".", "c.key"))
        self._assert_collision(privatekey_path=os.path.join(self.d, "sub", "..", "c.crt"))
        os.symlink(self.d, self._p("link"))
        self._assert_collision(chain_path=os.path.join(self._p("link"), "c.key"))

    def test_provided_csr_cert_path_ends_in_key_is_not_a_collision(self):
        csr = self._provided_csr()[1]
        self.cert = self._p("c.key")
        self.assertFalse(self._build(csr_path=csr).privatekey_filename)

    # --- unreadable private key: clean failure, key file left alone ---------------------------
    def _assert_unreadable(self, vc):
        with self.assertRaises(_Fail) as ctx:
            vc.check(validate=False)
        self.assertIn("Failed to load private key file", str(ctx.exception))

    def test_encrypted_key_without_passphrase_fails_cleanly(self):
        self._write("c.key", _key_pem(_new_key(), "secret"))
        self._assert_unreadable(self._build())                      # no certificate yet
        self._write("c.crt", _Issued().cert, 0o644)
        self._assert_unreadable(self._build())                      # certificate present

    def test_wrong_passphrase_fails_cleanly(self):
        key = _new_key()
        self._write("c.key", _key_pem(key, "secret"))
        self._write("c.crt", _Issued(key).cert, 0o644)
        self._assert_unreadable(self._build(privatekey_passphrase="wrong"))
        self.assertFalse(self._build(privatekey_passphrase="secret").check(validate=False)["changed"])

    def test_garbage_key_fails_cleanly(self):
        self._write("junk.pem", "not a key\n")
        self._assert_unreadable(self._build(privatekey_path=self._p("junk.pem")))
        self._write("c.crt", _Issued().cert, 0o644)
        self._assert_unreadable(self._build(privatekey_path=self._p("junk.pem")))
        self.assertEqual(open(self._p("junk.pem")).read(), "not a key\n")

    # --- mode never leaves group/other access on the key / PKCS#12 ----------------------------
    def test_mode_0644_key_gets_0600_and_is_idempotent(self):
        vc = self._build(mode="0644")
        vc.enroll()
        self.assertEqual(stat.S_IMODE(os.stat(self._p("c.key")).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.cert).st_mode), 0o644)
        vc.validate()  # RC2: "Insufficient file permissions" (key left at 0644)
        self.assertFalse(self._build(mode="0644").check(validate=False)["changed"])

    def test_mode_0640_explicit_key(self):
        key_path = self._p("k.pem")
        vc = self._build(mode="0640", privatekey_path=key_path, privatekey_type="ECDSA", privatekey_curve="P256")
        vc.enroll()
        self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.cert).st_mode), 0o640)
        vc.validate()

    def test_mode_0644_pkcs12_gets_0600(self):
        self.cert = self._p("c.p12")
        vc = self._build(mode="0644", use_pkcs12_format=True)
        vc.enroll()
        self.assertEqual(stat.S_IMODE(os.stat(self.cert).st_mode), 0o600)
        vc.validate()

    def test_stricter_mode_is_kept(self):
        vc = self._build(mode="0400")
        vc.enroll()
        self.assertEqual(stat.S_IMODE(os.stat(self._p("c.key")).st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(os.stat(self.cert).st_mode), 0o400)
        vc.validate()


if __name__ == "__main__":
    unittest.main()
