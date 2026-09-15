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
import os
import unittest

from vcert.parser import json_parser
from vcert.errors import VenafiError, VenafiConnectionError

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
        'policy_spec_path': SOURCE_PATH,
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
