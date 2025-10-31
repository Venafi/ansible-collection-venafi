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

from plugins.modules.venafi_ssh_certificate import VSSHCertificate
from test_utils import FakeModule, FAKE, TPP_TOKEN_URL, TPP_USER, TPP_PASSWORD, TPP_ACCESS_TOKEN

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


class TestSSHCertificate(unittest.TestCase):
    def test_request_cert(self):
        params = get_params()
        # params['policy_spec_output_path'] = CURRENT_DIR + '/assets/ps_output_tpp.json'
        module = FakeModule(params)
        vcert = VSSHCertificate(module)
        resp = vcert.get_policy()
        print("Get Policy Finished")


def get_params():
    params = {
        'test_mode': True if FAKE in ('True', 'true', 'TRUE') else False,
        'url': TPP_TOKEN_URL,
        'user': TPP_USER,
        'password': TPP_PASSWORD,
        'access_token': TPP_ACCESS_TOKEN,
        'trust_bundle': False,
    }
    return params
