import unittest

from plugins.module_utils import common_utils
from plugins.module_utils.common_utils import (
    get_venafi_connection,
    is_ngts_request,
    fail_if_ngts,
)


class Fail(Exception):
    pass


def base_params(**overrides):
    """Build a full module.params dict (every key get_venafi_connection reads)."""
    params = {
        'test_mode': False,
        'url': None,
        'user': None,
        'password': None,
        'token': None,
        'access_token': None,
        'trust_bundle': None,
        'client_id': None,
        'client_secret': None,
        'token_url': None,
        'tsg_id': None,
        'scope': None,
    }
    params.update(overrides)
    return params


class FakeModule(object):
    def __init__(self, params):
        self.params = params
        self.warnings = []
        self.fail_code = None

    def warn(self, msg):
        self.warnings.append(msg)

    def fail_json(self, **kwargs):
        self.fail_code = kwargs
        raise Fail(kwargs.get('msg'))


class RecordingFactory(object):
    """Stand-in for vcert.venafi_connection that records the kwargs it was called with."""
    def __init__(self):
        self.called_with = None

    def __call__(self, **kwargs):
        self.called_with = kwargs
        return 'ngts-connection'


class TestNgtsDetection(unittest.TestCase):
    def test_is_ngts_request_true_when_both_present(self):
        module = FakeModule(base_params(client_id='cid', client_secret='secret'))
        self.assertTrue(is_ngts_request(module))

    def test_is_ngts_request_false_when_only_one_present(self):
        self.assertFalse(is_ngts_request(FakeModule(base_params(client_id='cid'))))
        self.assertFalse(is_ngts_request(FakeModule(base_params(client_secret='secret'))))

    def test_is_ngts_request_false_for_tpp_and_cloud(self):
        self.assertFalse(is_ngts_request(FakeModule(base_params(url='https://tpp', access_token='tok'))))
        self.assertFalse(is_ngts_request(FakeModule(base_params(token='apikey'))))


class TestGetVenafiConnectionNgts(unittest.TestCase):
    def setUp(self):
        self.factory = RecordingFactory()
        self._orig = getattr(common_utils, 'venafi_connection', None)
        common_utils.venafi_connection = self.factory

    def tearDown(self):
        if self._orig is not None:
            common_utils.venafi_connection = self._orig
        else:
            delattr(common_utils, 'venafi_connection')

    def test_selects_ngts_and_forces_platform(self):
        # client_id + client_secret -> NGTS, selected by forcing the platform.
        module = FakeModule(base_params(
            client_id='cid', client_secret='secret', tsg_id='1000000001',
        ))
        result = get_venafi_connection(module)
        self.assertEqual(result, 'ngts-connection')
        self.assertIsNotNone(self.factory.called_with)
        self.assertEqual(self.factory.called_with['client_id'], 'cid')
        self.assertEqual(self.factory.called_with['client_secret'], 'secret')
        self.assertEqual(self.factory.called_with['tsg_id'], '1000000001')
        # platform is forced to NGTS rather than relying on auto-detection
        self.assertEqual(getattr(self.factory.called_with['platform'], 'name', None), 'NGTS')

    def test_url_and_token_url_omitted_forwarded_as_none_for_prod_default(self):
        # url and token_url are optional; both forwarded as None so the SDK applies its
        # production defaults.
        module = FakeModule(base_params(
            client_id='cid', client_secret='secret', tsg_id='1000000001',
        ))
        get_venafi_connection(module)
        self.assertIsNone(self.factory.called_with['url'])
        self.assertIsNone(self.factory.called_with['token_url'])

    def test_non_prod_urls_forwarded(self):
        module = FakeModule(base_params(
            client_id='cid', client_secret='secret', scope='tsg_id:1000000001',
            url='https://dev.api/ngts', token_url='https://dev.auth/token',
        ))
        get_venafi_connection(module)
        self.assertEqual(self.factory.called_with['url'], 'https://dev.api/ngts')
        self.assertEqual(self.factory.called_with['token_url'], 'https://dev.auth/token')
        self.assertEqual(self.factory.called_with['scope'], 'tsg_id:1000000001')

    def test_token_url_not_required(self):
        # token_url is optional now that the SDK defaults it to the production endpoint:
        # omitting it (with no access_token) must not fail fast.
        module = FakeModule(base_params(client_id='cid', client_secret='secret', tsg_id='1000000001'))
        result = get_venafi_connection(module)
        self.assertEqual(result, 'ngts-connection')
        self.assertIsNone(module.fail_code)
        self.assertIsNone(self.factory.called_with['token_url'])

    def test_access_token_forwarded(self):
        # A pre-issued access_token is forwarded to the SDK.
        module = FakeModule(base_params(
            client_id='cid', client_secret='secret', tsg_id='1000000001',
            access_token='pre.issued.token',
        ))
        result = get_venafi_connection(module)
        self.assertEqual(result, 'ngts-connection')
        self.assertEqual(self.factory.called_with['access_token'], 'pre.issued.token')

    def test_requires_tsg_or_scope(self):
        module = FakeModule(base_params(
            client_id='cid', client_secret='secret', token_url='https://auth/token',
        ))
        self.assertRaises(Fail, get_venafi_connection, module)
        self.assertIn('tsg_id', module.fail_code['msg'])

    def test_partial_creds_client_id_only_fails(self):
        # client_id without client_secret must not fall through to the TPP/SaaS path.
        module = FakeModule(base_params(client_id='cid', tsg_id='1000000001'))
        self.assertRaises(Fail, get_venafi_connection, module)
        self.assertIn('client_secret', module.fail_code['msg'])
        self.assertIsNone(self.factory.called_with)

    def test_partial_creds_client_secret_only_fails(self):
        # client_secret without client_id must not fall through to the TPP/SaaS path.
        module = FakeModule(base_params(client_secret='secret', scope='tsg_id:1000000001'))
        self.assertRaises(Fail, get_venafi_connection, module)
        self.assertIn('client_id', module.fail_code['msg'])
        self.assertIsNone(self.factory.called_with)

    def test_ngts_only_field_without_client_creds_fails(self):
        # An NGTS-only field (tsg_id) with no client credentials is an incomplete NGTS attempt.
        module = FakeModule(base_params(tsg_id='1000000001'))
        self.assertRaises(Fail, get_venafi_connection, module)
        self.assertIn('client_id', module.fail_code['msg'])
        self.assertIn('client_secret', module.fail_code['msg'])
        self.assertIsNone(self.factory.called_with)


class TestRealSdkContract(unittest.TestCase):
    """Exercise get_venafi_connection against the real vcert SDK (not the mock) to lock the
    public API contract the collection depends on. Skips cleanly if vcert is not installed.

    NGTSConnection / FakeConnection construct offline (auth is lazy), so these stay unit tests.
    """
    def setUp(self):
        try:
            from vcert.connection_ngts import NGTSConnection  # noqa: F401
            from vcert import FakeConnection  # noqa: F401
        except ImportError:
            self.skipTest("vcert SDK not installed")

    def test_ngts_creds_yield_real_ngts_connection(self):
        from vcert.connection_ngts import NGTSConnection
        module = FakeModule(base_params(
            client_id='cid', client_secret='secret', tsg_id='1000000001',
        ))
        conn = get_venafi_connection(module)
        self.assertIsInstance(conn, NGTSConnection)
        self.assertIsNone(module.fail_code)

    def test_test_mode_yields_fake_connection_for_ngts(self):
        # test_mode short-circuits to the SDK's fake connector even on the NGTS path.
        from vcert import FakeConnection
        module = FakeModule(base_params(
            test_mode=True, client_id='cid', client_secret='secret', tsg_id='1000000001',
        ))
        conn = get_venafi_connection(module)
        self.assertIsInstance(conn, FakeConnection)


class TestFailIfNgts(unittest.TestCase):
    def test_blocks_when_ngts_creds_present(self):
        module = FakeModule(base_params(client_id='cid', client_secret='secret'))
        self.assertRaises(Fail, fail_if_ngts, module, 'policy management')
        self.assertIn('policy management', module.fail_code['msg'])

    def test_allows_when_no_ngts_creds(self):
        module = FakeModule(base_params(url='https://tpp', access_token='tok'))
        # should not raise
        fail_if_ngts(module, 'policy management')
        self.assertIsNone(module.fail_code)


if __name__ == '__main__':
    unittest.main()
