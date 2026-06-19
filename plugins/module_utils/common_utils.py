#!/usr/bin/env python
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
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

HAS_VCERT = True
try:
    from vcert import Connection, venafi_connection, IssuerHint, Authentication, VenafiPlatform
except ImportError:
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
# NGTS (Strata Cloud Manager) OAuth2 service-account options
F_CLIENT_ID = 'client_id'
F_CLIENT_SECRET = 'client_secret'
F_TOKEN_URL = 'token_url'
F_TSG_ID = 'tsg_id'
F_SCOPE = 'scope'

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
        # NGTS (Strata Cloud Manager) OAuth2 service-account credentials. The connection
        # is auto-detected as NGTS when client_id and client_secret are supplied. url and
        # token_url are optional and default to the Palo Alto production endpoints.
        client_id=dict(type='str', required=False, default=None, no_log=True),
        client_secret=dict(type='str', required=False, default=None, no_log=True),
        token_url=dict(type='str', required=False, default=None, no_log=False),
        tsg_id=dict(type='str', required=False, default=None),
        scope=dict(type='str', required=False, default=None),
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


def is_ngts_request(module):
    """
    Returns True when NGTS (Strata Cloud Manager) credentials are supplied. Mirrors the SDK's
    auto-detection: the client_id/client_secret pair is NGTS-specific.

    :param ansible.module_utils.basic.AnsibleModule module:
    :rtype: bool
    """
    return bool(module.params.get(F_CLIENT_ID) and module.params.get(F_CLIENT_SECRET))


def any_ngts_field_present(module):
    """
    Returns True when any NGTS (Strata Cloud Manager) specific field is supplied. Used to tell an
    incomplete NGTS attempt apart from a plain TPP/SaaS request so we can fail with a targeted
    message instead of letting it fall through to the wrong backend.

    :param ansible.module_utils.basic.AnsibleModule module:
    :rtype: bool
    """
    return any(module.params.get(f) for f in (F_CLIENT_ID, F_CLIENT_SECRET, F_TOKEN_URL, F_TSG_ID, F_SCOPE))


def fail_if_ngts(module, operation):
    """
    Fail fast with a clear message when NGTS credentials are supplied to a module that does not
    support NGTS. NGTS supports certificate operations only (no policy management, no SSH).

    :param ansible.module_utils.basic.AnsibleModule module:
    :param str operation: human-readable name of the unsupported operation, for the message
    :rtype: None
    """
    if is_ngts_request(module):
        module.fail_json(
            msg="NGTS (Strata Cloud Manager) supports certificate operations only; %s is not "
                "available for NGTS. Use the venafi_certificate module instead." % operation
        )


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
    client_id = module.params[F_CLIENT_ID]
    client_secret = module.params[F_CLIENT_SECRET]
    token_url = module.params[F_TOKEN_URL]
    tsg_id = module.params[F_TSG_ID]
    scope = module.params[F_SCOPE]

    # test_mode must yield the SDK fake connector for every backend. The NGTS branch below
    # forces platform=NGTS, and venafi_connection() ignores the fake flag whenever a platform
    # is set, so short-circuit here before backend selection to keep test_mode consistent.
    if test_mode:
        return venafi_connection(fake=True)

    if is_ngts_request(module):
        # NGTS requires the OAuth2 service-account pair plus a scope (or tsg_id to derive it).
        # url and token_url are optional: the SDK defaults both to the Palo Alto production
        # endpoints (and warns when it falls back to the production token_url), so non-production
        # environments must set them explicitly. Force the NGTS platform so selection does not
        # depend on which optional fields happen to be set.
        if not tsg_id and not scope:
            module.fail_json(msg="NGTS requires 'tsg_id' or 'scope' in addition to "
                                 "'client_id' and 'client_secret'.")
        return venafi_connection(
            url=url,
            access_token=access_token,
            http_request_kwargs={"verify": trust_bundle} if trust_bundle else None,
            fake=test_mode,
            platform=VenafiPlatform.NGTS,
            client_id=client_id,
            client_secret=client_secret,
            token_url=token_url,
            tsg_id=tsg_id,
            scope=scope,
        )

    if any_ngts_field_present(module):
        # NGTS-specific fields were supplied but client_id/client_secret are not both present.
        # Fail with a targeted message instead of silently routing to the TPP/SaaS path.
        missing = [f for f in (F_CLIENT_ID, F_CLIENT_SECRET) if not module.params.get(f)]
        module.fail_json(msg="NGTS (Strata Cloud Manager) requires both 'client_id' and "
                             "'client_secret'. Missing: %s." % ", ".join(missing))

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
