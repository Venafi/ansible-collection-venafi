"""
VC-59232 regression tests (local CSR on any backend).

Two bugs the ticket surfaced on NGTS & CMSaaS (backend-agnostic — the connection is mocked here):

  #2  Default local CSR (no privatekey_type) never wrote the private key, because
      `serialize_private_key` was only set inside `elif self.privatekey_type:`. vcert generates the
      key and populates cert.key, but the module skipped writing it -> validation then failed with
      "Private key file does not contain a valid private key".

  #3  `check()` appended to `self.changed_message` without resetting it, so `main()` running
      `check()` then `validate()`->`check()` produced duplicated error text ("... | ...").
"""
import os
import unittest
from collections import defaultdict
from unittest import mock

from plugins.modules.venafi_certificate import VCertificate
from vcert import ZoneConfig, CertField

CERT_PATH = "/tmp/vc59232_cert.pem"
CHAIN_PATH = "/tmp/vc59232_chain.pem"
PRIV_PATH = "/tmp/vc59232_priv.pem"


class _Fail(Exception):
    pass


class FakeModule(object):
    """Minimal AnsibleModule stand-in that also supports the file helpers enroll() uses."""

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

    # used by _atomic_write / _check_and_update_permissions
    def atomic_move(self, src, dst):
        os.replace(src, dst)

    def load_file_common_arguments(self, params):
        return {}

    def set_fs_attributes_if_different(self, file_args, changed):
        return False


class _FakeCert(object):
    def __init__(self):
        self.cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        self.chain = ["-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"]
        self.full_chain = self.cert + self.chain[0]
        self.key = "-----BEGIN RSA PRIVATE KEY-----\nCCCC\n-----END RSA PRIVATE KEY-----\n"


def _rm(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


BASE_PARAMS = {
    "cert_path": CERT_PATH,
    "chain_path": CHAIN_PATH,
    "privatekey_path": PRIV_PATH,
    "common_name": "vc59232.venafi.example.com",
    "before_expired_hours": 72,
    "test_mode": True,          # -> FakeConnection at construction (we then replace it with a mock)
    "csr_origin": "local",
    "privatekey_reuse": True,   # the argspec default
    "issuer_hint": "DEFAULT",
    "chain_option": "last",
    "zone": "",
}


def _zone_config():
    return ZoneConfig(
        organization=CertField(""), organizational_unit=CertField(""),
        country=CertField(""), province=CertField(""), locality=CertField(""),
        policy=None, key_type=None,
    )


def _build(extra=None):
    params = dict(BASE_PARAMS)
    if extra:
        params.update(extra)
    vc = VCertificate(FakeModule(params))
    conn = mock.Mock()
    conn.read_zone_conf.return_value = _zone_config()
    conn.request_cert.return_value = True
    conn.retrieve_cert.return_value = _FakeCert()
    vc.connection = conn
    return vc


class TestVC59232LocalCsr(unittest.TestCase):
    def setUp(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def tearDown(self):
        _rm(CERT_PATH, CHAIN_PATH, PRIV_PATH)

    def test_default_local_csr_writes_private_key(self):
        # BUG #2: default local CSR (no privatekey_type) must WRITE the private key file.
        vc = _build()
        vc.enroll()
        self.assertTrue(
            os.path.exists(PRIV_PATH),
            "default local CSR did not write the private key file (VC-59232 #2)")

    def test_explicit_type_local_csr_writes_private_key(self):
        # Control: with privatekey_type set it already worked (the ticket's workaround).
        vc = _build({"privatekey_type": "RSA", "privatekey_size": 2048})
        vc.enroll()
        self.assertTrue(os.path.exists(PRIV_PATH))

    def test_local_csr_without_privatekey_path_writes_derived_key(self):
        # Follow-up: with privatekey_path omitted, serialize_private_key=True previously called
        # _atomic_write(None, ...) -> TypeError. The key path is now derived from cert_path
        # ("placed near certificate with key suffix"), so the key is written and no crash occurs.
        derived = os.path.splitext(CERT_PATH)[0] + ".key"
        _rm(derived)
        try:
            vc = _build({"privatekey_path": None})
            self.assertEqual(vc.privatekey_filename, derived)
            vc.enroll()
            self.assertTrue(os.path.exists(derived),
                            "local CSR without privatekey_path did not write the derived key file")
        finally:
            _rm(derived)

    def test_check_twice_does_not_duplicate_messages(self):
        # BUG #3: check() then validate()->check() must not accumulate duplicate messages.
        vc = _build()
        vc.check(validate=False)
        result = vc.check(validate=False)
        segs = [s for s in result["changed_msg"].split(" | ") if s]
        self.assertEqual(
            len(segs), len(set(segs)),
            "check() produced duplicate messages (VC-59232 #3): %r" % result["changed_msg"])


if __name__ == "__main__":
    unittest.main()
