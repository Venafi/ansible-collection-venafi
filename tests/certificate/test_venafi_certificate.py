import unittest
import shutil
import os
from collections import namedtuple, defaultdict
from plugins.modules.venafi_certificate import VCertificate

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


testAsset = namedtuple("testAssert", "is_valid cert chain private_key password common_name alt_name id")

CERT_PATH = "/tmp/cert.pem"
CHAIN_PATH = "/tmp/chain.pem"
PRIV_PATH = "/tmp/priv.pem"


class Fail(Exception):
    pass


class FakeModule(object):
    def __init__(self, asset):
        self.fail_code = None
        self.exit_code = None
        self.warn =  str
        self.params = defaultdict(lambda: None)
        self.params["cert_path"] = CERT_PATH
        self.params["chain_path"] = CHAIN_PATH
        self.params["privatekey_path"] = PRIV_PATH
        self.params["common_name"] = asset.common_name
        self.params["before_expired_hours"] = 72
        if asset.alt_name:
            self.params["alt_name"] = [x.strip() for x in asset.alt_name.split(',')]
        self.params["test_mode"] = True

    def exit_json(self, **kwargs):
        self.exit_code = kwargs

    def fail_json(self, **kwargs):
        self.fail_code = kwargs
        raise Fail(self.fail_code['msg'])


class TestVcertificate(unittest.TestCase):
    def test_validate(self):
        for asset in TEST_ASSETS:
            print("testing asset id %s" % asset.id)
            create_testfiles(asset)
            module = FakeModule(asset)
            vcert = VCertificate(module)
            if asset.is_valid:
                vcert.validate()
                self.assertIsNone(module.fail_code)
            else:
                self.assertRaises(Fail, vcert.validate)


def create_testfiles(asset):
    """
    :param testAsset asset:
    """
    for p, v in ((CERT_PATH, asset.cert), (CHAIN_PATH, asset.chain), (PRIV_PATH, asset.private_key)):

        shutil.copy(CURRENT_DIR + "/assets/" + v, p)


TEST_ASSETS = [
    # TODO check error message, not just valid\invalid
    # simple valid
    testAsset(is_valid=True,  cert="valid_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem",
              private_key="valid_rsa2048_key.pem", password=None, common_name="test111.venafi.example.com",
              alt_name=None, id=1),
    # another cn
    testAsset(is_valid=False, cert="valid_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem",
              private_key="valid_rsa2048_key.pem", password=None, common_name="test1111.venafi.example.com",
              alt_name=None, id=2),
    # corrupted file
    testAsset(is_valid=False, cert="invalid_cert.pem", chain="valid_rsa2048_chain.pem",
              private_key="valid_rsa2048_key.pem", password=None, common_name="test111.venafi.example.com",
              alt_name=None, id=3),
    # unmatched cn
    testAsset(is_valid=False, cert="invalid_cn_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem",
              private_key="valid_rsa2048_key.pem", password=None, common_name="test111.venafi.example.com",
              alt_name=None, id=4),
    # unmatched key type
    testAsset(is_valid=False, cert="valid_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem",
              private_key="valid_ec_key.pem", password=None, common_name="test1111.venafi.example.com",
              alt_name=None, id=5),
    # valid with dns
    testAsset(is_valid=True, cert="valid_alt_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem",
              private_key="valid_alt_rsa2048_key.pem", password=None, common_name="test123.venafi.example.com",
              alt_name="IP:192.168.1.1,DNS:www.venafi.example.com,DNS:m.venafi.example.com,email:e@venafi.com,"
                       "email:e2@venafi.com,IP Address:192.168.2.2", id=6),
    # invalid with dns
    testAsset(is_valid=False, cert="valid_alt_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem",
              private_key="valid_alt_rsa2048_key.pem", password=None, common_name="test123.venafi.example.com",
              alt_name="IP:192.168.1.1,DNS:www.venafi.example.com,DNS:m.venafi.example.com,email:e@venafi.com,"
                       "email:e2@venafi.com", id=7),
    # expired
    testAsset(is_valid=False, cert="invalid_date_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem",
              private_key="valid_rsa2048_key.pem", password=None, common_name="test123.venafi.example.com",
              alt_name=None, id=8)
]

