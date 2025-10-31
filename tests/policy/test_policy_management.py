#
# Copyright 2021 Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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

from plugins.modules.venafi_policy import VPolicyManagement
from test_utils import FakeModule, FAKE, TPP_ACCESS_TOKEN, TPP_TOKEN_URL, CLOUD_URL, CLOUD_APIKEY, CLOUD_ZONE, \
    TPP_TRUST_BUNDLE, TPP_ZONE

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_PATH = '/tmp/ps_source.json'


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
