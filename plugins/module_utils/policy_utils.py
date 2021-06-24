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
from vcert.parser import FIELD_OWNERS, FIELD_APPROVERS, FIELD_USER_ACCESS, FIELD_DOMAINS, FIELD_POLICY, \
    FIELD_WILDCARD_ALLOWED, FIELD_MAX_VALID_DAYS, FIELD_CERTIFICATE_AUTHORITY, FIELD_AUTOINSTALLED, FIELD_SUBJECT, \
    FIELD_ORGS, FIELD_ORG_UNITS, FIELD_LOCALITIES, FIELD_STATES, FIELD_COUNTRIES, FIELD_KEY_PAIR, \
    FIELD_SERVICE_GENERATED, FIELD_REUSE_ALLOWED, FIELD_RSA_KEY_SIZES, FIELD_ELLIPTIC_CURVES, FIELD_KEY_TYPES, \
    FIELD_SUBJECT_ALT_NAMES, FIELD_DNS_ALLOWED, FIELD_EMAIL_ALLOWED, FIELD_IP_ALLOWED, FIELD_UPN_ALLOWED, \
    FIELD_URI_ALLOWED, FIELD_DEFAULTS, FIELD_DEFAULT_DOMAIN, FIELD_DEFAULT_AUTOINSTALLED, FIELD_DEFAULT_SUBJECT, \
    FIELD_DEFAULT_ORG, FIELD_DEFAULT_LOCALITY, FIELD_DEFAULT_STATE, FIELD_DEFAULT_COUNTRY, FIELD_DEFAULT_KEY_PAIR, \
    FIELD_DEFAULT_ELLIPTIC_CURVE, FIELD_DEFAULT_RSA_KEY_SIZE, FIELD_DEFAULT_SERVICE_GENERATED, FIELD_DEFAULT_KEY_TYPE, \
    FIELD_USERS
from vcert.policy import PolicySpecification

ERR_MSG = '%s changed. Local: %s Remote: %s'
EMPTY_MSG = '%s structure is empty on %s but exists on %s'
LOCAL = 'Local'
REMOTE = 'Remote'


def _get_err_msg(name, local, remote):
    if isinstance(local, list):
        local_str = ''
        remote_str = ''
        for x in local:
            local_str += x.__str__() + ','
        for y in remote:
            remote_str += y.__str__() + ','
        local_str = '[%s]' % local_str[:len(local_str) - 1]
        remote_str = '[%s]' % remote_str[:len(remote_str) - 1]
        return ERR_MSG % (name, local_str, remote_str)
    else:
        return ERR_MSG % (name, local, remote)


def _get_empty_msg(name, empty_type):
    """

    :param str name:
    :param str empty_type:
    :rtype: str
    """
    if empty_type == LOCAL:
        return EMPTY_MSG % (name, LOCAL, REMOTE)
    elif empty_type == REMOTE:
        return EMPTY_MSG % (name, REMOTE, LOCAL)
    return ''


def check_policy_specification(local_ps, remote_ps):
    """
    Validates that all values present in the source PolicySpecification match with
    the current output PolicySpecification
    :param PolicySpecification local_ps:
    :param PolicySpecification remote_ps:
    :rtype: tuple[bool, list[str]]
    """
    is_changed = False
    msgs = []

    list_fields = []
    value_fields = []

    list_fields.append((FIELD_OWNERS, remote_ps.owners, local_ps.owners))
    list_fields.append((FIELD_USERS, remote_ps.users, local_ps.users))
    list_fields.append((FIELD_APPROVERS, remote_ps.approvers, local_ps.approvers))

    value_fields.append((FIELD_USER_ACCESS, remote_ps.user_access, local_ps.user_access))

    # Validating Policy
    empty_local_p = _is_empty_object(local_ps.policy)
    empty_remote_p = _is_empty_object(remote_ps.policy)
    if empty_local_p and not empty_remote_p:
        is_changed = True
        msgs.append(_get_empty_msg('Policy', LOCAL))
    elif not empty_local_p and empty_remote_p:
        is_changed = True
        msgs.append(_get_empty_msg('Policy', REMOTE))
    elif not empty_local_p and not empty_remote_p:
        local_p = local_ps.policy
        remote_p = remote_ps.policy
        p = '%s.' % FIELD_POLICY

        list_fields.append((p + FIELD_DOMAINS, remote_p.domains, local_p.domains))

        value_fields.append((p + FIELD_WILDCARD_ALLOWED, local_p.wildcard_allowed, remote_p.wildcard_allowed))
        value_fields.append((p + FIELD_MAX_VALID_DAYS, local_p.max_valid_days, remote_p.max_valid_days))
        value_fields.append((p + FIELD_CERTIFICATE_AUTHORITY, local_p.certificate_authority,
                             remote_p.certificate_authority))
        value_fields.append((p + FIELD_AUTOINSTALLED, local_p.auto_installed, remote_p.auto_installed))

        # Validating Policy.Subject
        empty_local_subject = _is_empty_object(local_p.subject)
        empty_remote_subject = _is_empty_object(remote_p.subject)
        if empty_local_subject and not empty_remote_subject:
            is_changed = True
            msgs.append(_get_empty_msg('Policy.Subject', LOCAL))
        elif not empty_local_subject and empty_remote_subject:
            is_changed = True
            msgs.append(_get_empty_msg('Policy.Subject', REMOTE))
        elif not empty_local_subject and not empty_remote_subject:
            local_subject = local_p.subject
            remote_subject = remote_p.subject
            p = '%s.%s.' % (FIELD_POLICY, FIELD_SUBJECT)

            list_fields.append((p + FIELD_ORGS, local_subject.orgs, remote_subject.orgs))
            list_fields.append((p + FIELD_ORG_UNITS, local_subject.org_units, remote_subject.org_units))
            list_fields.append((p + FIELD_LOCALITIES, local_subject.localities, remote_subject.localities))
            list_fields.append((p + FIELD_STATES, local_subject.states, remote_subject.states))
            list_fields.append((p + FIELD_COUNTRIES, local_subject.countries, remote_subject.countries))

        # Validating Policy.KeyPair
        empty_local_kp = _is_empty_object(local_p.key_pair)
        empty_remote_kp = _is_empty_object(remote_p.key_pair)
        if empty_local_kp and not empty_remote_kp:
            is_changed = True
            msgs.append(_get_empty_msg('Policy.KeyPair', LOCAL))
        elif not empty_local_kp and empty_remote_kp:
            is_changed = True
            msgs.append(_get_empty_msg('Policy.KeyPair', REMOTE))
        elif not empty_local_kp and not empty_remote_kp:
            local_kp = local_p.key_pair
            remote_kp = remote_p.key_pair
            p = '%s.%s.' % (FIELD_POLICY, FIELD_KEY_PAIR)

            value_fields.append((p + FIELD_SERVICE_GENERATED, local_kp.service_generated, remote_kp.service_generated))
            value_fields.append((p + FIELD_REUSE_ALLOWED, local_kp.reuse_allowed, remote_kp.reuse_allowed))

            list_fields.append((p + FIELD_RSA_KEY_SIZES, local_kp.rsa_key_sizes, remote_kp.rsa_key_sizes))
            list_fields.append((p + FIELD_ELLIPTIC_CURVES, local_kp.elliptic_curves, remote_kp.elliptic_curves))

            if not _check_key_types(remote_kp.key_types, local_kp.key_types):
                is_changed = True
                msgs.append(_get_err_msg(p + FIELD_KEY_TYPES, local_kp.key_types, remote_kp.key_types))

        # Validating Policy.SubjectAltNames
        empty_local_sans = _is_empty_object(local_p.subject_alt_names)
        empty_remote_sans = _is_empty_object(remote_p.subject_alt_names)
        if empty_local_sans and not empty_remote_sans:
            is_changed = True
            msgs.append(_get_empty_msg('Policy.SubjectAltNames', LOCAL))
        elif not empty_local_sans and empty_remote_sans:
            is_changed = True
            msgs.append(_get_empty_msg('Policy.SubjectAltNames', REMOTE))
        elif not empty_local_sans and not empty_remote_sans:
            local_sans = local_p.subject_alt_names
            remote_sans = remote_p.subject_alt_names
            p = '%s.%s.' % (FIELD_POLICY, FIELD_SUBJECT_ALT_NAMES)

            value_fields.append((p + FIELD_DNS_ALLOWED, local_sans.dns_allowed, remote_sans.dns_allowed))
            value_fields.append((p + FIELD_EMAIL_ALLOWED, local_sans.email_allowed, remote_sans.email_allowed))
            value_fields.append((p + FIELD_IP_ALLOWED, local_sans.ip_allowed, remote_sans.ip_allowed))
            value_fields.append((p + FIELD_UPN_ALLOWED, local_sans.upn_allowed, remote_sans.upn_allowed))
            value_fields.append((p + FIELD_URI_ALLOWED, local_sans.uri_allowed, remote_sans.uri_allowed))

    # Validating Defaults
    empty_local_d = _is_empty_object(local_ps.defaults)
    empty_remote_d = _is_empty_object(remote_ps.defaults)
    if empty_local_d and not empty_remote_d:
        is_changed = True
        msgs.append(_get_empty_msg('Defaults', LOCAL))
    elif not empty_local_d and empty_remote_d:
        is_changed = True
        msgs.append(_get_empty_msg('Defaults', REMOTE))
    elif not empty_local_d and not empty_remote_d:
        local_d = local_ps.defaults
        remote_d = remote_ps.defaults
        p = '%s.' % FIELD_DEFAULTS

        value_fields.append((p + FIELD_DEFAULT_DOMAIN, local_d.domain, remote_d.domain))
        value_fields.append((p + FIELD_DEFAULT_AUTOINSTALLED, local_d.auto_installed, remote_d.auto_installed))

        # Validating Defaults.DefaultSubject
        empty_local_ds = _is_empty_object(local_d.subject)
        empty_remote_ds = _is_empty_object(remote_d.subject)
        if empty_local_ds and not empty_remote_ds:
            is_changed = True
            msgs.append(_get_empty_msg('Defaults.DefaultSubject', LOCAL))
        elif not empty_local_ds and empty_remote_ds:
            is_changed = True
            msgs.append(msgs.append('Defaults.DefaultSubject', REMOTE))
        elif not empty_local_ds and not empty_remote_ds:
            local_ds = local_d.subject
            remote_ds = remote_d.subject
            p = '%s.%s.' % (FIELD_DEFAULTS, FIELD_DEFAULT_SUBJECT)

            list_fields.append((remote_ds.org_units, local_ds.org_units))

            value_fields.append((p + FIELD_DEFAULT_ORG, local_ds.org, remote_ds.org))
            value_fields.append((p + FIELD_DEFAULT_LOCALITY, local_ds.locality, remote_ds.locality))
            value_fields.append((p + FIELD_DEFAULT_STATE, local_ds.state, remote_ds.state))
            value_fields.append((p + FIELD_DEFAULT_COUNTRY, local_ds.country, remote_ds.country))

        # Validating Defaults.DefaultKeyPair
        empty_local_dkp = _is_empty_object(local_d.key_pair)
        empty_remote_dkp = _is_empty_object(remote_d.key_pair)
        if empty_local_dkp and not empty_remote_dkp:
            is_changed = True
            msgs.append(_get_empty_msg('Defaults.DefaultKeyPair', LOCAL))
        elif not empty_local_dkp and empty_remote_dkp:
            is_changed = True
            msgs.append(_get_empty_msg('Defaults.DefaultKeyPair', REMOTE))
        elif not empty_local_dkp and not empty_remote_dkp:
            local_dkp = local_d.key_pair
            remote_dkp = remote_d.key_pair
            p = '%s.%s.' % (FIELD_DEFAULTS, FIELD_DEFAULT_KEY_PAIR)

            value_fields.append((p + FIELD_DEFAULT_ELLIPTIC_CURVE, local_dkp.elliptic_curve, remote_dkp.elliptic_curve))
            value_fields.append((p + FIELD_DEFAULT_RSA_KEY_SIZE, local_dkp.rsa_key_size, remote_dkp.rsa_key_size))
            value_fields.append((p + FIELD_DEFAULT_SERVICE_GENERATED, local_dkp.service_generated,
                                 remote_dkp.service_generated))

            if local_dkp.key_type.upper() != remote_dkp.key_type.upper():
                is_changed = True
                msgs.append(_get_err_msg(p + FIELD_DEFAULT_KEY_TYPE, local_dkp.key_type, remote_dkp.key_type))

    for name, local, remote in list_fields:
        if not _check_list(remote, local):
            is_changed = True
            msgs.append(_get_err_msg(name, local, remote))

    for name, local, remote in value_fields:
        if not _check_value(remote, local):
            is_changed = True
            msgs.append(_get_err_msg(name, local, remote))

    return is_changed, msgs


def _is_empty_object(obj):
    """

    :param object obj:  The object to check
    :return: True if and only if all the object's fields' values are None, empty or equivalent. False otherwise
    :rtype: bool
    """
    if obj is None:
        return True
    for k, v in obj.__dict__.items():
        if v is None:
            continue
        if isinstance(v, int):
            return False
        elif isinstance(v, str):
            if v != '':
                return False
            else:
                continue
        elif isinstance(v, bool):
            return False
        elif isinstance(v, list):
            if len(v) > 0:
                return False
            else:
                continue
        else:
            if not _is_empty_object(v):
                return False
    return True


def _check_list(remote_values, local_values):
    """
    Tests that all the elements of the sublist are present in the collection

    :param list remote_values: The tested values
    :param list local_values: The member values
    :rtype: bool
    """
    if len(remote_values) == len(local_values):
        return all(x in local_values for x in remote_values)
    else:
        return False


def _check_value(remote_value, local_value):
    """
    Validates if both parameters are equal.

    :param remote_value:
    :param local_value:
    :return: True if both parameters hold the same value, False otherwise
    :rtype: bool
    """
    if remote_value is not None and local_value is not None:
        return True if remote_value == local_value else False
    elif remote_value is None and local_value is None:
        return True
    else:
        return False


def _check_key_types(remote_values, local_values):
    """
    Validates that the key types match regardless of the casing. E.g. 'RSA' == 'rsa'
    :param list[str] remote_values:
    :param list[str] local_values:
    :rtype: bool
    """
    copy = []
    for val in local_values:
        copy.append(val.upper())
    if len(remote_values) == len(local_values):
        return all(x.upper() in copy for x in remote_values)
    else:
        return False
