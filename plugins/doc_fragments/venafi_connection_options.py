#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
            - The url of the CyberArk platform to connect to.
            - B(Required) for CyberArk Certificate Manager, Self-Hosted.
            - Optional for CyberArk Certificate Manager, SaaS. Only set the url when trying to reach a custom CyberArk Certificate Manager, SaaS platform (dev, QA, staging, etc.).
        default: null
        type: str

    user:
        description:
            - The username to authenticate at CyberArk Certificate Manager, Self-Hosted.
            - This option is deprecated. Use I(access_token) instead.
            - Ignored for CyberArk Certificate Manager, SaaS.
        default: null
        type: str

    password:
        description:
            - The password to authenticate at CyberArk Certificate Manager, Self-Hosted.
            - This option is deprecated. Use I(access_token) instead.
            - Ignored for CyberArk Certificate Manager, SaaS.
        default: null
        type: str

    token:
        description:
            - The api key to authenticate at CyberArk Certificate Manager, SaaS platform.
            - Required for CyberArk Certificate Manager, SaaS.
            - Ignored for CyberArk Certificate Manager, Self-Hosted.
        default: null
        type: str

    access_token:
        description:
            - The oauth token to authenticate at CyberArk Certificate Manager, Self-Hosted.
            - Use it instead of user/password combination.
            - Ignored for CyberArk Certificate Manager, SaaS.
        default: null
        type: str

    trust_bundle:
        description:
            - the path to a PEM file to be used as trust anchor when communicating with CyberArk Certificate Manager, Self-Hosted.
            - Ignored for CyberArk Certificate Manager, SaaS.
        default: null
        type: str
'''
