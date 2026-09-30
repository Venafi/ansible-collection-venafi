#
# Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

import requests
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes
from vcert.common import CommonConnection
from vcert.connection_cloud import CloudConnection
from vcert.connection_ngts import NGTSConnection
from vcert.connection_tpp_token import TPPTokenConnection
from vcert.parser import json_parser
from vcert.errors import VenafiError, VenafiConnectionError
from vcert.policy.policy_spec import DEFAULT_CA

from plugins.modules import venafi_policy
from plugins.modules.venafi_policy import VPolicyManagement
from test_utils import FakeModule, Fail, FAKE, TPP_ACCESS_TOKEN, TPP_TOKEN_URL, CLOUD_URL, CLOUD_APIKEY, CLOUD_ZONE, \
    TPP_TRUST_BUNDLE, TPP_ZONE

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_PATH = '/tmp/ps_source.json'


@unittest.skipUnless(TPP_ACCESS_TOKEN and TPP_TOKEN_URL,
                     "live TPP integration test; set TPP_ACCESS_TOKEN/TPP_TOKEN_URL to run")
class TestPolicyManagementTPP(unittest.TestCase):
    def test_get_policy(self):
        params = self.get_params()
        params['policy_spec_output_path'] = CURRENT_DIR + '/assets/ps_output_tpp.json'
        params['zone'] = TPP_ZONE
        module = FakeModule(params)
        vcert = VPolicyManagement(module)
        vcert.validate_local_path()
        check_result = vcert.check()
        vcert.set_policy()
        vcert.validate()
        vcert.module.exit_json(**check_result)
        print('Get Policy Finished')

    @staticmethod
    def get_params():
        return get_params(PLATFORM_TPP)


@unittest.skipUnless(CLOUD_APIKEY and CLOUD_URL,
                     "live VaaS integration test; set CLOUD_APIKEY/CLOUD_URL to run")
class TestPolicyManagementVaaS(unittest.TestCase):
    def test_get_policy(self):
        params = self.get_params()
        params['zone'] = CLOUD_ZONE
        params['policy_spec_output_path'] = CURRENT_DIR + '/assets/ps_output_vaas.json'
        module = FakeModule(params)
        vcert = VPolicyManagement(module)
        # resp = vcert.get_policy()
        ps = json_parser.parse_file('/Users/rvelamia/Venafi/ansible/policy/ps_test.json')
        # empty = is_empty_object(ps.defaults.subject)
        print('Get Policy Finished')

    @staticmethod
    def get_params():
        return get_params(PLATFORM_VAAS)


PLATFORM_TPP = 10
PLATFORM_VAAS = 100


def get_params(platform):
    params = {
        'test_mode': True if FAKE in ('True', 'true', 'TRUE') else False,
        'url': '',
        'user': '',
        'password': '',
        'access_token': '',
        'token': '',
        'trust_bundle': '',
        # NGTS connection fields read unconditionally by get_venafi_connection()
        'client_id': '',
        'client_secret': '',
        'token_url': '',
        'tsg_id': '',
        'scope': '',
        'zone': '',
        # Ansible always fills the canonical 'path' key (the 'policy_spec_path' alias is only an alias)
        'path': SOURCE_PATH,
        'policy_spec_output_path': '',
        'state': 'present',
        'force': False
    }
    if platform == PLATFORM_TPP:
        params['url'] = TPP_TOKEN_URL
        params['access_token'] = TPP_ACCESS_TOKEN
        params['trust_bundle'] = TPP_TRUST_BUNDLE
    elif platform == PLATFORM_VAAS:
        params['url'] = CLOUD_URL
        params['token'] = CLOUD_APIKEY

    return params


class _StubConn(object):
    """Minimal connection stub: get_policy either raises or returns a canned policy."""
    def __init__(self, exc=None, policy=None):
        self._exc = exc
        self._policy = policy

    def get_policy(self, zone):
        if self._exc is not None:
            raise self._exc
        return self._policy


def _bare_vpm(module, connection):
    """Build a VPolicyManagement offline, bypassing get_venafi_connection (no network)."""
    v = VPolicyManagement.__new__(VPolicyManagement)
    v.module = module
    v.state = module.params.get('state', 'present')
    v.force = module.params.get('force', False)
    v.zone = module.params.get('zone')
    v.local_ps = module.params.get('policy_spec_path')
    v.connection = connection
    v.is_tpp = module.params.get('is_tpp', False)  # test shim; real __init__ derives from connection
    return v


class TestPolicyCheckOffline(unittest.TestCase):
    """Offline coverage for check(): the test_mode fail-fast guard and the narrowed error handling
    (connection/auth errors surface; only a generic VenafiError is treated as 'policy absent')."""

    @staticmethod
    def _module(**overrides):
        params = {'test_mode': False, 'zone': 'my-cit', 'policy_spec_path': SOURCE_PATH,
                  'state': 'present', 'force': False}
        params.update(overrides)
        return FakeModule(params)

    def test_test_mode_fails_fast(self):
        module = self._module(test_mode=True)
        v = _bare_vpm(module, _StubConn(exc=NotImplementedError()))
        self.assertRaises(Fail, v.check)
        self.assertIn('test_mode', module.fail_code['msg'])

    def test_connection_error_is_surfaced(self):
        module = self._module()
        v = _bare_vpm(module, _StubConn(exc=VenafiConnectionError('token endpoint 500')))
        self.assertRaises(Fail, v.check)
        self.assertIn('Failed to read policy', module.fail_code['msg'])

    def test_generic_venafi_error_treated_as_absent(self):
        module = self._module()
        v = _bare_vpm(module, _StubConn(exc=VenafiError('policy not found')))
        result = v.check()
        self.assertTrue(result[venafi_policy.F_CHANGED])
        self.assertEqual(result[venafi_policy.F_POLICY_CREATED], 'my-cit')
        self.assertIsNone(module.fail_code)


def _full_params(**over):
    """A complete param dict (every field get_venafi_connection reads is present) with test_mode
    on, so the real VPolicyManagement.__init__ runs fully offline. policy_spec_path is deliberately
    NOT included unless overridden."""
    params = {
        'test_mode': True, 'url': None, 'user': None, 'password': None, 'access_token': None,
        'token': None, 'trust_bundle': None, 'client_id': None, 'client_secret': None,
        'token_url': None, 'tsg_id': None, 'scope': None, 'zone': 'my-cit',
        'state': 'present', 'force': False,
    }
    params.update(over)
    return params


class TestRegression140Module(unittest.TestCase):
    """Regression coverage at the module level for the 1.4.0 fixes."""

    def test_absent_without_policy_spec_path_no_keyerror(self):
        # Bug A: __init__ used module.params[F_PS_PATH]; the alias key is absent when the option is
        # omitted, so state=absent with no path raised KeyError before any logic ran.
        module = FakeModule(_full_params(state='absent'))
        v = VPolicyManagement(module)  # must NOT raise KeyError
        self.assertIsNone(v.local_ps)
        # check() then fails fast on test_mode with a clear message (not a raw traceback)
        self.assertRaises(Fail, v.check)
        self.assertIn('test_mode', module.fail_code['msg'])

    def test_present_without_policy_spec_path_no_keyerror(self):
        module = FakeModule(_full_params(state='present'))
        v = VPolicyManagement(module)  # must NOT raise KeyError
        self.assertIsNone(v.local_ps)

    def test_is_tpp_threaded_into_check(self):
        # Bug C wiring: check() must pass is_tpp so the CA comparison is backend-correct. A TPP
        # folder that locks no CA (remote CA "") vs a local file that omits CA must NOT churn.
        from vcert.policy.policy_spec import PolicySpecification, Policy, DEFAULT_CA
        src = '/tmp/reg140_local.json'
        with open(src, 'w') as fh:
            fh.write('{"policy": {"domains": ["example.com"], "maxValidDays": 90}}')
        remote = PolicySpecification(policy=Policy(domains=['example.com'], max_valid_days=90))
        remote.policy.certificate_authority = ''  # TPP folder with no CA locked

        tpp = _bare_vpm(FakeModule({'zone': 'z', 'state': 'present', 'policy_spec_path': src,
                                    'is_tpp': True}), _StubConn(policy=remote))
        self.assertFalse(tpp.check()[venafi_policy.F_CHANGED], 'TPP CA compare churned (bug C)')

        cloud = _bare_vpm(FakeModule({'zone': 'z', 'state': 'present', 'policy_spec_path': src,
                                      'is_tpp': False}), _StubConn(policy=remote))
        self.assertTrue(cloud.check()[venafi_policy.F_CHANGED],
                        'Cloud/NGTS effective-CA reset should still be reported')
        os.remove(src)


# ----------------------------------------------------------------------------------------------------
# SaaS "policy not found" classification (M26) and connection-error surfacing (M57).
# The errors are produced by vcert's real process_server_response() and, where possible, by the real
# connector code path with only the HTTP transport (requests.get/post) replaced.
# ----------------------------------------------------------------------------------------------------
SAAS_URL = 'https://api.venafi.cloud/'
SAAS_ZONE = 'My App\\My CIT'
SAAS_TEMPLATE_URL = SAAS_URL + 'outagedetection/v1/applications/My%20App/certificateissuingtemplates/My%20CIT'
SAAS_CA_ACCOUNT_URL = SAAS_URL + 'v1/certificateauthorities/BUILTIN/accounts/acc-1'
BODY_10051 = {'errors': [{'code': 10051, 'message': 'Unable to find application or issuing template', 'args': []}]}
# The live SaaS API (dev251, 2026-09-24) answers the template read with HTTP 404 and these bodies
BODY_20215 = {'errors': [{'code': 20215, 'message': 'Application with name My App not found', 'args': ['My App']}]}
BODY_20216 = {'errors': [{'code': 20216, 'message': 'No certificate issuing template with alias My CIT has been '
                                                    'assigned to application with name My App',
                          'args': ['My CIT', 'My App']}]}
# ...and these non-JSON pages for a malformed name ('%' in the zone), a bad API key and a '/' in the alias
BODY_JETTY_400 = (b'<html>\n<head>\n<meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>\n'
                  b'<title>Error 400 Ambiguous URI path encoding</title>\n</head>\n<body>\n'
                  b'<h2>HTTP ERROR 400 Ambiguous URI path encoding</h2>\n</body>\n</html>\n')
BODY_INVALID_KEY = b'Invalid API key'
BODY_FORBIDDEN = b'Forbidden'
BODY_OTHER = {'errors': [{'code': 20000, 'message': 'Not Found'}]}
BODY_401 = {'errors': [{'code': 10501, 'message': 'Unauthorized'}]}


def _http_response(status, body, url, content_type='application/json'):
    r = requests.Response()
    r.status_code = status
    r._content = body if isinstance(body, bytes) else json.dumps(body).encode()
    r.headers['content-type'] = content_type
    r.request = requests.Request('GET', url).prepare()
    r.url = url
    return r


def _sdk_error(status, body, url=SAAS_TEMPLATE_URL):
    """The exact VenafiConnectionError vcert raises for an HTTP error response."""
    try:
        CommonConnection.process_server_response(_http_response(status, body, url))
    except VenafiConnectionError as e:
        return e
    raise AssertionError('process_server_response did not raise for HTTP %s' % status)


def _check_module(zone=SAAS_ZONE, state='present'):
    return FakeModule({'test_mode': False, 'zone': zone, 'policy_spec_path': SOURCE_PATH,
                       'state': state, 'force': False})


class TestSaasPolicyNotFound(unittest.TestCase):
    """check() on a real CloudConnection: SaaS answers a missing Application/issuing template with an
    HTTP error. Not found only for a JSON error body with code 10051/20215/20216 and a status other than
    401/403; HTML and plain-text error pages are real errors."""

    def _saas_check(self, status, body, state='present', content_type='application/json'):
        module = _check_module(state=state)
        v = _bare_vpm(module, CloudConnection(token='fake-api-key', url=SAAS_URL))
        with mock.patch('requests.get',
                        side_effect=lambda url, **kw: _http_response(status, body, url, content_type)) as get:
            try:
                result = v.check()
            except Fail:
                result = None
        # the real connector read the template endpoint and nothing else
        self.assertEqual(get.call_args_list[0][0][0], SAAS_TEMPLATE_URL)
        return module, result

    def assertNotFound(self, status, body):
        module, result = self._saas_check(status, body)
        self.assertIsNone(module.fail_code)
        self.assertTrue(result[venafi_policy.F_CHANGED])
        self.assertEqual(result[venafi_policy.F_POLICY_CREATED], SAAS_ZONE)
        module, result = self._saas_check(status, body, state='absent')
        self.assertIsNone(module.fail_code)
        self.assertFalse(result[venafi_policy.F_CHANGED])

    def assertFailsClearly(self, status, body, content_type='application/json'):
        module, result = self._saas_check(status, body, content_type=content_type)
        self.assertIsNone(result)
        self.assertIn('Failed to read policy %s' % SAAS_ZONE, module.fail_code['msg'])
        self.assertIn('Server status: %s' % status, module.fail_code['msg'])

    def test_missing_application_is_not_found(self):
        self.assertNotFound(404, BODY_20215)

    def test_alias_not_assigned_to_application_is_not_found(self):
        self.assertNotFound(404, BODY_20216)

    def test_code_10051_is_not_found(self):
        self.assertNotFound(400, BODY_10051)
        self.assertNotFound(404, BODY_10051)

    def test_400_without_not_found_code_fails(self):
        self.assertFailsClearly(400, BODY_OTHER)
        self.assertFailsClearly(400, BODY_JETTY_400, content_type='text/html;charset=iso-8859-1')

    def test_404_without_not_found_code_fails(self):
        self.assertFailsClearly(404, BODY_OTHER)
        self.assertFailsClearly(404, b'<html>Not Found</html>', content_type='text/html')

    def test_401_fails(self):
        self.assertFailsClearly(401, BODY_INVALID_KEY, content_type='text/plain')
        self.assertFailsClearly(401, BODY_401)
        self.assertFailsClearly(401, BODY_20215)  # 401 is an auth error even if the body says not found

    def test_403_fails(self):
        self.assertFailsClearly(403, BODY_FORBIDDEN, content_type='text/plain')
        self.assertFailsClearly(403, {'errors': [{'code': 10502, 'message': 'Forbidden'}]})
        self.assertFailsClearly(403, BODY_20216)

    def test_500_fails(self):
        self.assertFailsClearly(500, {'errors': [{'code': 99999, 'message': 'Internal server error'}]})
        self.assertFailsClearly(500, b'', content_type='text/plain')

    def test_400_from_another_saas_endpoint_fails(self):
        # Only the template read is classified; a 400 from e.g. the CA-account lookup is a real error.
        conn = CloudConnection(token='fake-api-key', url=SAAS_URL)
        conn.get_policy = mock.Mock(side_effect=_sdk_error(400, BODY_10051, url=SAAS_CA_ACCOUNT_URL))
        module = _check_module()
        self.assertRaises(Fail, _bare_vpm(module, conn).check)
        self.assertIn('certificateauthorities', module.fail_code['msg'])

    def test_predicate(self):
        saas = CloudConnection(token='fake-api-key', url=SAAS_URL)
        cases = [(404, BODY_20215, True), (404, BODY_20216, True), (400, BODY_10051, True), (404, BODY_10051, True),
                 (500, BODY_10051, True), (400, BODY_OTHER, False), (400, BODY_JETTY_400, False),
                 (400, b'', False), (404, BODY_OTHER, False), (401, BODY_INVALID_KEY, False),
                 (401, BODY_10051, False), (401, BODY_401, False), (403, BODY_FORBIDDEN, False),
                 (403, BODY_20215, False), (403, BODY_OTHER, False), (500, BODY_OTHER, False),
                 (404, b'not json', False), (404, b'[]', False), (404, b'{"errors": [1]}', False),
                 (404, b'{"errors": [{"code": "20215"}]}', False)]
        for status, body, expected in cases:
            with self.subTest(status=status, body=body):
                self.assertEqual(venafi_policy._is_saas_zone_not_found(saas, _sdk_error(status, body)), expected)
        self.assertFalse(venafi_policy._is_saas_zone_not_found(saas, VenafiConnectionError('token 500')))
        self.assertFalse(venafi_policy._is_saas_zone_not_found(saas, VenafiError('not found')))


class TestNotFoundUnchangedForNgtsAndTpp(unittest.TestCase):
    """NGTS and Self-Hosted keep their own not-found shapes; the SaaS classification never applies."""

    @staticmethod
    def _ngts():
        return NGTSConnection(client_id='cid', client_secret='csec', tsg_id='1234567890',
                              token_url='https://auth.example.com/oauth2/token', url='https://ngts.example.com/ngts')

    @staticmethod
    def _token_response(url, **kwargs):
        return _http_response(200, {'access_token': 'tok', 'token_type': 'Bearer', 'expires_in': 900}, url)

    def test_ngts_missing_cit_is_absent(self):
        module = _check_module(zone='my-cit')
        v = _bare_vpm(module, self._ngts())
        with mock.patch('requests.post', side_effect=self._token_response), \
                mock.patch('requests.get', side_effect=lambda url, **kw: _http_response(
                    200, {'certificateIssuingTemplates': []}, url)):
            result = v.check()
        self.assertIsNone(module.fail_code)
        self.assertEqual(result[venafi_policy.F_POLICY_CREATED], 'my-cit')

    def test_ngts_http_error_with_saas_shape_still_fails(self):
        conn = self._ngts()
        conn.get_policy = mock.Mock(side_effect=_sdk_error(400, BODY_10051))
        module = _check_module(zone='my-cit')
        self.assertRaises(Fail, _bare_vpm(module, conn).check)
        self.assertIn('Failed to read policy my-cit', module.fail_code['msg'])

    def test_tpp_missing_policy_is_absent(self):
        module = _check_module(zone='example\\missing')
        v = _bare_vpm(module, TPPTokenConnection(url='https://tpp.example.com', access_token='tok'))
        with mock.patch('requests.post', side_effect=lambda url, **kw: _http_response(
                200, {'Result': 400, 'Error': 'Object does not exist'}, url)):
            result = v.check()
        self.assertIsNone(module.fail_code)
        self.assertEqual(result[venafi_policy.F_POLICY_CREATED], 'example\\missing')

    def test_tpp_http_400_fails(self):
        module = _check_module(zone='example\\policy')
        v = _bare_vpm(module, TPPTokenConnection(url='https://tpp.example.com', access_token='tok'))
        with mock.patch('requests.post', side_effect=lambda url, **kw: _http_response(400, BODY_10051, url)):
            self.assertRaises(Fail, v.check)
        self.assertIn('Server status: 400', module.fail_code['msg'])


class TestTransportErrorsSurfaced(unittest.TestCase):
    """A mistyped/unreachable url or token_url raises a requests exception (not a VenafiError). It must
    fail the task with a clear message instead of escaping as a raw MODULE FAILURE traceback."""

    def _ngts_check_with_token_post(self, **post):
        module = _check_module(zone='my-cit')
        v = _bare_vpm(module, TestNotFoundUnchangedForNgtsAndTpp._ngts())
        with mock.patch('requests.post', **post):
            self.assertRaises(Fail, v.check)
        self.assertIn('Failed to read policy my-cit', module.fail_code['msg'])
        return module.fail_code['msg']

    def test_unresolvable_token_url(self):
        msg = self._ngts_check_with_token_post(
            side_effect=requests.exceptions.ConnectionError('Failed to resolve auth.exampel.com'))
        self.assertIn('Failed to resolve', msg)

    def test_token_url_returning_html(self):
        self._ngts_check_with_token_post(side_effect=lambda url, **kw: _http_response(
            200, b'<html>login</html>', url, content_type='text/html'))

    def test_token_url_http_error(self):
        msg = self._ngts_check_with_token_post(side_effect=lambda url, **kw: _http_response(404, b'', url))
        self.assertIn('Failed to obtain access token', msg)

    def test_unreachable_saas_url(self):
        module = _check_module()
        v = _bare_vpm(module, CloudConnection(token='fake-api-key', url=SAAS_URL))
        with mock.patch('requests.get', side_effect=requests.exceptions.ConnectionError('Connection refused')):
            self.assertRaises(Fail, v.check)
        self.assertIn('Connection refused', module.fail_code['msg'])


# ----------------------------------------------------------------------------------------------------
# Policy file argument (M3): run the real module entry point so Ansible's argspec handling (alias ->
# canonical 'path', type=path expansion) is exercised. test_mode makes check() stop right after
# validate_local_path(), so reaching the test_mode message proves the file was found.
# ----------------------------------------------------------------------------------------------------
class TestPolicyPathArgument(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.spec = os.path.join(self.home, 'policy.json')
        with open(self.spec, 'w') as fh:
            fh.write('{"policy": {"domains": ["example.com"]}}')

    def tearDown(self):
        shutil.rmtree(self.home)

    def _run_main(self, **args):
        args.update({'test_mode': True, 'zone': 'my-cit'})
        out = io.StringIO()
        # ansible-core >= 2.19 also requires a serialization profile next to the module args
        # (create=True keeps this working on 2.15, which has no such attribute).
        with mock.patch.object(basic, '_ANSIBLE_ARGS', to_bytes(json.dumps({'ANSIBLE_MODULE_ARGS': args}))), \
                mock.patch.object(basic, '_ANSIBLE_PROFILE', 'legacy', create=True), \
                mock.patch.dict(os.environ, {'HOME': self.home}), redirect_stdout(out):
            with self.assertRaises(SystemExit):
                venafi_policy.main()
        return json.loads(out.getvalue())['msg']

    def assertFileFound(self, msg):
        self.assertIn('not supported in test_mode', msg)

    def test_canonical_path(self):
        self.assertFileFound(self._run_main(path=self.spec))

    def test_policy_spec_path_alias(self):
        self.assertFileFound(self._run_main(policy_spec_path=self.spec))

    def test_tilde_is_expanded(self):
        self.assertFileFound(self._run_main(path='~/policy.json'))
        self.assertFileFound(self._run_main(policy_spec_path='~/policy.json'))

    def test_missing_file_still_reported(self):
        self.assertIn('policy_spec_path field not defined', self._run_main())
        self.assertIn('does not exist', self._run_main(path=os.path.join(self.home, 'nope.json')))


# ----------------------------------------------------------------------------------------------------
# Self-Hosted (TPP) apply must not write the SaaS built-in CA (M9). Real TPPTokenConnection.set_policy
# with the HTTP transport recorded.
# ----------------------------------------------------------------------------------------------------
class TestTppDefaultCaNotWritten(unittest.TestCase):
    SPEC = {'policy': {'domains': ['example.com'], 'wildcardAllowed': True,
                       'subject': {'orgs': ['Example'], 'orgUnits': ['IT'], 'localities': ['Salt Lake'],
                                   'states': ['Utah'], 'countries': ['US']},
                       'keyPair': {'keyTypes': ['RSA'], 'rsaKeySizes': [2048]}}}
    REAL_CA = '\\VED\\Policy\\Certificate Authorities\\MS CA'

    def setUp(self):
        fd, self.src = tempfile.mkstemp(suffix='.json')
        os.close(fd)

    def tearDown(self):
        os.remove(self.src)

    def _apply(self, policy_exists, ca=None):
        spec = json.loads(json.dumps(self.SPEC))
        if ca:
            spec['policy']['certificateAuthority'] = ca
        with open(self.src, 'w') as fh:
            json.dump(spec, fh)
        calls = []

        def post(url, json=None, **kw):
            calls.append((url.rsplit('/vedsdk/', 1)[1], json))
            if url.endswith('config/isvalid'):
                exists = policy_exists or not json['ObjectDN'].endswith('\\new')
                body = {'Result': 1, 'Object': {'TypeName': 'Policy'}} if exists else \
                    {'Result': 400, 'Error': 'Object does not exist'}
                return _http_response(200, body, url)
            return _http_response(200, {'Result': 1}, url)

        module = FakeModule({'zone': 'example\\new', 'state': 'present', 'policy_spec_path': self.src,
                             'is_tpp': True})
        v = _bare_vpm(module, TPPTokenConnection(url='https://tpp.example.com', access_token='tok'))
        with mock.patch('requests.post', side_effect=post), \
                mock.patch('requests.get', side_effect=lambda url, **kw: _http_response(
                    200, {'Version': '25.3.0.2740'}, url)):
            v.set_policy()
        self.assertIsNone(module.fail_code)
        return [(path, body['AttributeName'], body.get('Values')) for path, body in calls
                if body and body.get('AttributeName') == 'Certificate Authority']

    def test_create_with_omitted_ca_writes_no_ca(self):
        self.assertEqual(self._apply(policy_exists=False), [])

    def test_create_with_explicit_builtin_ca_writes_no_ca(self):
        self.assertEqual(self._apply(policy_exists=False, ca=DEFAULT_CA), [])

    def test_update_with_omitted_ca_resets_but_does_not_write_ca(self):
        self.assertEqual(self._apply(policy_exists=True),
                         [('config/clearpolicyattribute', 'Certificate Authority', None)])

    def test_explicit_real_ca_is_written(self):
        self.assertEqual(self._apply(policy_exists=False, ca=self.REAL_CA),
                         [('config/writepolicy', 'Certificate Authority', [self.REAL_CA])])

    def test_saas_and_ngts_keep_builtin_ca(self):
        # The SaaS/NGTS connectors need the CA (they default it themselves); only TPP drops it.
        with open(self.src, 'w') as fh:
            json.dump(self.SPEC, fh)
        conn = mock.Mock()
        v = _bare_vpm(FakeModule({'zone': 'app\\cit', 'state': 'present', 'policy_spec_path': self.src,
                                  'is_tpp': False}), conn)
        v.set_policy()
        self.assertEqual(conn.set_policy.call_args[0][1].policy.certificate_authority, DEFAULT_CA)
