#!/usr/bin/env python
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
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

try:
    from vcert import Connection, venafi_connection, IssuerHint, Authentication
except ImportError:
    HAS_VCERT = True
else:
    HAS_VCERT = False

F_TEST_MODE = 'test_mode'
F_URL = 'url'
F_USER = 'user'
F_PASSWORD = 'password'
F_APIKEY = 'token'
F_ACCESS_TOKEN = 'access_token'
F_TRUST_BUNDLE = 'trust_bundle'
F_STATE = 'state'
F_FORCE = 'force'
F_STATE_PRESENT = 'present'
F_STATE_ABSENT = 'absent'

DEFAULT = 'DEFAULT'
DIGICERT = 'DIGICERT'
ENTRUST = 'ENTRUST'
MICROSOFT = 'MICROSOFT'


def venafi_common_argument_spec():
    """
    Returns a dict containing common options required to connect to a CyberArk platform
    :return: dict
    """
    options = dict(
        test_mode=dict(type='bool', required=False, default=False),
        url=dict(type='str', required=False, default=None),
        user=dict(type='str', required=False, default=None, no_log=True),
        password=dict(type='str', required=False, default=None, no_log=True),
        token=dict(type='str', required=False, default=None, no_log=True),
        access_token=dict(type='str', required=False, default=None, no_log=True),
        trust_bundle=dict(type='str', required=False),
    )
    return options


def module_common_argument_spec():
    """
    Returns a dict containing common options used by ansible modules
    :return: dict
    """
    options = dict(
        state=dict(type='str', choices=[F_STATE_PRESENT, F_STATE_ABSENT], default=F_STATE_PRESENT),
        force=dict(type='bool', default=False),
    )
    return options


def get_venafi_connection(module, platform=None):
    """

    :param ansible.module_utils.basic.AnsibleModule module:
    :param VenafiPlatform platform:
    :return: a connection to an instance of a CyberArk platform
    :rtype: vcert.CommonConnection
    """
    test_mode = module.params[F_TEST_MODE]
    url = module.params[F_URL]
    user = module.params[F_USER]
    password = module.params[F_PASSWORD]
    access_token = module.params[F_ACCESS_TOKEN]
    apikey = module.params[F_APIKEY]
    trust_bundle = module.params[F_TRUST_BUNDLE]

    if user != '' or password != '':
        module.warn("user/password authentication is deprecated. Use access token instead.")

    # Legacy Connection. Deprecated. Do not use
    if user and password:
        return Connection(
            url=url, user=user, password=password,
            http_request_kwargs=({"verify": trust_bundle} if trust_bundle else None),
            fake=test_mode,
        )
    else:
        return venafi_connection(url=url,
                                 access_token=access_token,
                                 api_key=apikey,
                                 http_request_kwargs={"verify": trust_bundle} if trust_bundle else None,
                                 fake=test_mode,
                                 platform=platform)


def get_access_token(connector, user, password, scope):
    """
    Requests an access token from the connector with the given scope

    :param CommonConnection connector:
    :param str user:
    :param str password:
    :param str scope:
    :rtype: None
    """
    auth = Authentication(user=user, password=password, scope=scope)
    connector.get_access_token(auth)


def get_issuer_hint(hint):
    if not hint:
        return None
    elif hint == DIGICERT:
        return IssuerHint.DIGICERT
    elif hint == ENTRUST:
        return IssuerHint.ENTRUST
    elif hint == MICROSOFT:
        return IssuerHint.MICROSOFT
    elif hint == DEFAULT:
        return IssuerHint.DEFAULT
    else:
        raise VenafiAnsibleError("Issuer Hint not valid: %s" % hint)


class VenafiAnsibleError(Exception):
    pass
