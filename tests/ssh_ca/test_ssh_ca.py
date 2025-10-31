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
from os import environ
import unittest

from plugins.modules.venafi_ssh_ca import VSSHCertAuthority
from tests.policy.test_utils import FakeModule

TPP_TOKEN_URL = environ.get("TPP_TOKEN_URL")
TPP_ACCESS_TOKEN = environ.get("TPP_ACCESS_TOKEN")
TPP_TRUST_BUNDLE = environ.get("TPP_TRUST_BUNDLE")


class TestSSHCertificate(unittest.TestCase):
    def test_retrieve_ca_public_key_no_auth(self):
        params = get_params()
        module = FakeModule(params)
        vcert = VSSHCertAuthority(module)
        result = vcert.retrieve_ssh_config()
        print("Retrieve CA public key finished with result: %s", result)

    def test_retrieve_ca_public_key_auth(self):
        params = get_params(use_credentials=True)
        module = FakeModule(params)
        vcert = VSSHCertAuthority(module)
        result = vcert.retrieve_ssh_config()
        print("Retrieve CA public key and principals finished with result: %s", result)


def get_params(use_credentials=False):
    params = {
        'test_mode': False,
        'url': TPP_TOKEN_URL,
        'trust_bundle': TPP_TRUST_BUNDLE if TPP_TRUST_BUNDLE else None
    }
    if use_credentials:
        params['access_token'] = TPP_ACCESS_TOKEN
    return params
