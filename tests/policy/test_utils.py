#!/usr/bin/env python3
#
# Copyright 2021 Venafi, Inc.
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

FAKE = environ.get('FAKE')
TPP_URL = environ.get('TPP_URL')
TPP_USER = environ.get('TPP_USER')
TPP_PASSWORD = environ.get('TPP_PASSWORD')
TPP_ZONE = environ.get('TPP_ZONE')
TPP_ZONE_ECDSA = environ.get('TPP_ZONE_ECDSA')
TPP_TOKEN_URL = environ.get("TPP_TOKEN_URL")
TPP_ACCESS_TOKEN = environ.get("TPP_ACCESS_TOKEN")
TPP_TRUST_BUNDLE = environ.get("TPP_TRUST_BUNDLE")
CLOUD_URL = environ.get('CLOUD_URL')
CLOUD_APIKEY = environ.get('CLOUD_APIKEY')
CLOUD_ZONE = environ.get('CLOUD_ZONE')


class Fail(Exception):
    pass


class FakeModule(object):
    def __init__(self, params=None):
        """
        :param dict params: parameters to be used by the module
        """
        self.fail_code = None
        self.exit_code = None
        self.warn = str
        self.params = params if params else dict()

    def exit_json(self, **kwargs):
        self.exit_code = kwargs

    def fail_json(self, **kwargs):
        self.fail_code = kwargs
        raise Fail(self.fail_code['msg'])
