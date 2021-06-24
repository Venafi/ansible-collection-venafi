#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
class ModuleDocFragment(object):
    DOCUMENTATION = '''
options:
    test_mode:
        description:
            - If C(true) a Fake connection will be created.
            - Use only for testing purposes.
        default: false
        type: bool

    url:
        description:
            - The url of the Venafi platform to connect to.
            - Required for Venafi TPP.
            - Optional for VaaS. Only set the url when trying to reach
            a custom VaaS platform (like development)
        default: ''
        type: str

    user:
        description:
            - The username to authenticate at Venafi TPP.
            - This option is deprecated. Use I(access_token) instead.
            - Ignored for VaaS.
        default: ''
        type: str

    password:
        description:
            - The password to authenticate at Venafi TPP.
            - This option is deprecated. Use I(access_token) instead.
            - Ignored for VaaS.
        default: ''
        type: str

    token:
        description:
            - The api key to authenticate at VaaS platform
            - Required for VaaS
            - Ignored for Venafi TPP
        default: ''
        type: str

    access_token:
        description:
            - The oauth token to authenticate at Venafi TPP.
            - Use it instead of user/password combination.
            - Ignored for VaaS.
        default: ''
        type: str

    trust_bundle:
        description:
            - the path to a PEM file to be used as trust anchor when
            communicating with Venafi TPP.
            - Ignored for VaaS
        default: ''
        type: str
'''
