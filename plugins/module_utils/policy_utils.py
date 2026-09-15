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

from collections import Counter

HAS_VCERT = True
try:
    from vcert.parser import FIELD_OWNERS, FIELD_APPROVERS, FIELD_USER_ACCESS, FIELD_DOMAINS, FIELD_POLICY, \
        FIELD_WILDCARD_ALLOWED, FIELD_MAX_VALID_DAYS, FIELD_CERTIFICATE_AUTHORITY, FIELD_AUTOINSTALLED, FIELD_SUBJECT, \
        FIELD_ORGS, FIELD_ORG_UNITS, FIELD_LOCALITIES, FIELD_STATES, FIELD_COUNTRIES, FIELD_KEY_PAIR, \
        FIELD_SERVICE_GENERATED, FIELD_REUSE_ALLOWED, FIELD_RSA_KEY_SIZES, FIELD_ELLIPTIC_CURVES, FIELD_KEY_TYPES, \
        FIELD_SUBJECT_ALT_NAMES, FIELD_DNS_ALLOWED, FIELD_EMAIL_ALLOWED, FIELD_IP_ALLOWED, FIELD_UPN_ALLOWED, \
        FIELD_URI_ALLOWED, FIELD_URI_PROTOCOLS, FIELD_IP_CONSTRAINTS, FIELD_DEFAULTS, FIELD_DEFAULT_DOMAIN, \
        FIELD_DEFAULT_AUTOINSTALLED, FIELD_DEFAULT_SUBJECT, FIELD_DEFAULT_ORG, FIELD_DEFAULT_LOCALITY, \
        FIELD_DEFAULT_STATE, FIELD_DEFAULT_COUNTRY, FIELD_DEFAULT_KEY_PAIR, FIELD_DEFAULT_ELLIPTIC_CURVE, \
        FIELD_DEFAULT_RSA_KEY_SIZE, FIELD_DEFAULT_SERVICE_GENERATED, FIELD_DEFAULT_KEY_TYPE, FIELD_USERS
    from vcert.policy.policy_spec import DEFAULT_CA
except ImportError:
    HAS_VCERT = False
    DEFAULT_CA = None

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


def _append_value(value_fields, name, local, remote):
    """
    Queue a scalar field for comparison, but only when the local spec actually sets it.

    A policy file that omits a field parses to None, which means 'unspecified' -- not 'set to
    empty'. get_policy always returns the platform's real value, so comparing an omitted local
    field against a populated remote reports a false 'changed' on every run and breaks idempotency
    for minimal/declarative policy files. This mirrors the empty-local skip already used for
    SubjectAltNames and certificateAuthority. Note booleans: an explicit False is compared (False
    is not None); only an omitted (None) field is skipped. Use force=true to re-apply regardless.
    """
    if local is not None:
        value_fields.append((name, local, remote))


def _append_list(list_fields, name, local, remote):
    """
    Queue a list field for comparison, but only when the local spec provides a non-empty list.
    An omitted/empty local list means 'unspecified' (see _append_value).
    """
    if local:
        list_fields.append((name, local, remote))


def check_policy_specification(local_ps, remote_ps, ignore_owners_users=False):
    """
    Validates that all values present in the source vcert.policy.PolicySpecification match with
    the current output PolicySpecification.

    Fields, lists and nested blocks that the local spec omits are treated as 'unspecified' and are
    skipped rather than reported as changed: get_policy always returns the platform's full state,
    so comparing an omitted local value against a populated remote would report a false 'changed'
    on every run (breaking idempotency for minimal/declarative policy files). Only values the local
    spec actually declares are diffed. force=true remains the escape hatch to re-apply regardless.

    :param vcert.policy.PolicySpecification local_ps:
    :param vcert.policy.PolicySpecification remote_ps:
    :param bool ignore_owners_users: skip owners/users/approvers/user_access comparison. NGTS
        (Strata Cloud Manager) has no Application/owner layer, so get_policy always returns them
        empty and set_policy ignores them; comparing a local file that lists them would report
        changed forever (parity with the Go NGTS connector).
    :rtype: tuple[bool, list[str]]
    """
    is_changed = False
    msgs = []

    list_fields = []
    value_fields = []

    if not ignore_owners_users:
        _append_list(list_fields, FIELD_OWNERS, local_ps.owners, remote_ps.owners)
        _append_list(list_fields, FIELD_USERS, local_ps.users, remote_ps.users)
        _append_list(list_fields, FIELD_APPROVERS, local_ps.approvers, remote_ps.approvers)
        _append_value(value_fields, FIELD_USER_ACCESS, local_ps.user_access, remote_ps.user_access)

    # Validating Policy. An omitted local 'policy' block means 'unspecified' -> skip; only a
    # locally-declared policy that the remote lacks is a genuine change.
    if not _is_empty_object(local_ps.policy):
        if _is_empty_object(remote_ps.policy):
            is_changed = True
            msgs.append(_get_empty_msg('Policy', REMOTE))
        else:
            local_p = local_ps.policy
            remote_p = remote_ps.policy
            p = '%s.' % FIELD_POLICY

            _append_list(list_fields, p + FIELD_DOMAINS, local_p.domains, remote_p.domains)

            _append_value(value_fields, p + FIELD_WILDCARD_ALLOWED, local_p.wildcard_allowed,
                          remote_p.wildcard_allowed)
            _append_value(value_fields, p + FIELD_MAX_VALID_DAYS, local_p.max_valid_days, remote_p.max_valid_days)
            # certificate_authority is always compared against the EFFECTIVE CA that set_policy will
            # apply. The vcert SDK (like the Go/Terraform BuildCloudCitRequest) defaults an omitted
            # CA to the built-in DEFAULT_CA and sends exactly that, so the diff must reflect the CA
            # apply would set (declarative parity with vcert Go / terraform-provider-venafi). An
            # omitted or explicit built-in CA that would reset a real remote CA is therefore reported
            # as a change instead of being silently skipped; it converges after one apply.
            effective_local_ca = local_p.certificate_authority or DEFAULT_CA
            if not _check_value(remote_p.certificate_authority, effective_local_ca):
                is_changed = True
                msgs.append(_get_err_msg(p + FIELD_CERTIFICATE_AUTHORITY, effective_local_ca,
                                         remote_p.certificate_authority))
            _append_value(value_fields, p + FIELD_AUTOINSTALLED, local_p.auto_installed, remote_p.auto_installed)

            # Validating Policy.Subject
            if not _is_empty_object(local_p.subject):
                if _is_empty_object(remote_p.subject):
                    is_changed = True
                    msgs.append(_get_empty_msg('Policy.Subject', REMOTE))
                else:
                    local_subject = local_p.subject
                    remote_subject = remote_p.subject
                    p = '%s.%s.' % (FIELD_POLICY, FIELD_SUBJECT)

                    _append_list(list_fields, p + FIELD_ORGS, local_subject.orgs, remote_subject.orgs)
                    _append_list(list_fields, p + FIELD_ORG_UNITS, local_subject.org_units, remote_subject.org_units)
                    _append_list(list_fields, p + FIELD_LOCALITIES, local_subject.localities,
                                 remote_subject.localities)
                    _append_list(list_fields, p + FIELD_STATES, local_subject.states, remote_subject.states)
                    _append_list(list_fields, p + FIELD_COUNTRIES, local_subject.countries, remote_subject.countries)

            # Validating Policy.KeyPair
            if not _is_empty_object(local_p.key_pair):
                if _is_empty_object(remote_p.key_pair):
                    is_changed = True
                    msgs.append(_get_empty_msg('Policy.KeyPair', REMOTE))
                else:
                    local_kp = local_p.key_pair
                    remote_kp = remote_p.key_pair
                    p = '%s.%s.' % (FIELD_POLICY, FIELD_KEY_PAIR)

                    _append_value(value_fields, p + FIELD_SERVICE_GENERATED, local_kp.service_generated,
                                  remote_kp.service_generated)
                    _append_value(value_fields, p + FIELD_REUSE_ALLOWED, local_kp.reuse_allowed,
                                  remote_kp.reuse_allowed)

                    _append_list(list_fields, p + FIELD_RSA_KEY_SIZES, local_kp.rsa_key_sizes, remote_kp.rsa_key_sizes)

                    # elliptic_curves is case-insensitive (the platform returns UPPERCASE curves,
                    # e.g. "P256", while users write them lowercase) and compared only when the
                    # local spec lists curves.
                    if local_kp.elliptic_curves and not _check_list_case_insensitive(
                            remote_kp.elliptic_curves, local_kp.elliptic_curves):
                        is_changed = True
                        msgs.append(_get_err_msg(p + FIELD_ELLIPTIC_CURVES, local_kp.elliptic_curves,
                                                 remote_kp.elliptic_curves))

                    if local_kp.key_types and not _check_key_types(remote_kp.key_types, local_kp.key_types):
                        is_changed = True
                        msgs.append(_get_err_msg(p + FIELD_KEY_TYPES, local_kp.key_types, remote_kp.key_types))

            # Validating Policy.SubjectAltNames. An empty local SANs block means 'unspecified':
            # remote policy always carries SANs, so comparing would be a false positive.
            if not _is_empty_object(local_p.subject_alt_names):
                if _is_empty_object(remote_p.subject_alt_names):
                    is_changed = True
                    msgs.append(_get_empty_msg('Policy.SubjectAltNames', REMOTE))
                else:
                    local_sans = local_p.subject_alt_names
                    remote_sans = remote_p.subject_alt_names
                    p = '%s.%s.' % (FIELD_POLICY, FIELD_SUBJECT_ALT_NAMES)

                    _append_value(value_fields, p + FIELD_DNS_ALLOWED, local_sans.dns_allowed, remote_sans.dns_allowed)
                    _append_value(value_fields, p + FIELD_EMAIL_ALLOWED, local_sans.email_allowed,
                                  remote_sans.email_allowed)
                    _append_value(value_fields, p + FIELD_IP_ALLOWED, local_sans.ip_allowed, remote_sans.ip_allowed)
                    _append_value(value_fields, p + FIELD_UPN_ALLOWED, local_sans.upn_allowed, remote_sans.upn_allowed)
                    _append_value(value_fields, p + FIELD_URI_ALLOWED, local_sans.uri_allowed, remote_sans.uri_allowed)

                    # uri_protocols / ip_constraints were previously never diffed, so changing the
                    # allowed protocols or IP constraints (with the *_allowed flag unchanged) was a
                    # silently missed drift. Compare only when the local spec lists them. Protocol
                    # tokens (https/ldaps) are matched case-insensitively, like the curve/key-type
                    # comparisons above.
                    if local_sans.uri_protocols and not _check_list_case_insensitive(
                            remote_sans.uri_protocols, local_sans.uri_protocols):
                        is_changed = True
                        msgs.append(_get_err_msg(p + FIELD_URI_PROTOCOLS, local_sans.uri_protocols,
                                                 remote_sans.uri_protocols))
                    _append_list(list_fields, p + FIELD_IP_CONSTRAINTS, local_sans.ip_constraints,
                                 remote_sans.ip_constraints)

    # Validating Defaults
    if not _is_empty_object(local_ps.defaults):
        if _is_empty_object(remote_ps.defaults):
            is_changed = True
            msgs.append(_get_empty_msg('Defaults', REMOTE))
        else:
            local_d = local_ps.defaults
            remote_d = remote_ps.defaults
            p = '%s.' % FIELD_DEFAULTS

            _append_value(value_fields, p + FIELD_DEFAULT_DOMAIN, local_d.domain, remote_d.domain)
            _append_value(value_fields, p + FIELD_DEFAULT_AUTOINSTALLED, local_d.auto_installed,
                          remote_d.auto_installed)

            # Validating Defaults.DefaultSubject
            if not _is_empty_object(local_d.subject):
                if _is_empty_object(remote_d.subject):
                    is_changed = True
                    msgs.append(_get_empty_msg('Defaults.DefaultSubject', REMOTE))
                else:
                    local_ds = local_d.subject
                    remote_ds = remote_d.subject
                    p = '%s.%s.' % (FIELD_DEFAULTS, FIELD_DEFAULT_SUBJECT)

                    _append_list(list_fields, p + FIELD_ORG_UNITS, local_ds.org_units, remote_ds.org_units)

                    _append_value(value_fields, p + FIELD_DEFAULT_ORG, local_ds.org, remote_ds.org)
                    _append_value(value_fields, p + FIELD_DEFAULT_LOCALITY, local_ds.locality, remote_ds.locality)
                    _append_value(value_fields, p + FIELD_DEFAULT_STATE, local_ds.state, remote_ds.state)
                    _append_value(value_fields, p + FIELD_DEFAULT_COUNTRY, local_ds.country, remote_ds.country)

            # Validating Defaults.DefaultKeyPair
            if not _is_empty_object(local_d.key_pair):
                if _is_empty_object(remote_d.key_pair):
                    is_changed = True
                    msgs.append(_get_empty_msg('Defaults.DefaultKeyPair', REMOTE))
                else:
                    local_dkp = local_d.key_pair
                    remote_dkp = remote_d.key_pair
                    p = '%s.%s.' % (FIELD_DEFAULTS, FIELD_DEFAULT_KEY_PAIR)

                    _append_value(value_fields, p + FIELD_DEFAULT_RSA_KEY_SIZE, local_dkp.rsa_key_size,
                                  remote_dkp.rsa_key_size)
                    _append_value(value_fields, p + FIELD_DEFAULT_SERVICE_GENERATED, local_dkp.service_generated,
                                  remote_dkp.service_generated)

                    # default elliptic_curve: None-safe, case-insensitive, compared only when set.
                    lc = local_dkp.elliptic_curve
                    rc = remote_dkp.elliptic_curve
                    if lc is not None and lc.upper() != (rc.upper() if rc else rc):
                        is_changed = True
                        msgs.append(_get_err_msg(p + FIELD_DEFAULT_ELLIPTIC_CURVE, local_dkp.elliptic_curve,
                                                 remote_dkp.elliptic_curve))

                    # default key_type: None-safe, case-insensitive, compared only when set.
                    lkt = local_dkp.key_type
                    rkt = remote_dkp.key_type
                    if lkt is not None and lkt.upper() != (rkt.upper() if rkt else rkt):
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
    Order-independent multiset equality of two lists (None treated as empty).

    A plain "same length and every remote value is in local" check reports equal for
    ([1, 1], [1, 2]) and is asymmetric, so it can miss a genuine drift. Counter equality is
    exact multiset equality.

    :param list remote_values: The tested values
    :param list local_values: The member values
    :rtype: bool
    """
    return Counter(remote_values or []) == Counter(local_values or [])


def _check_list_case_insensitive(remote_values, local_values):
    """
    Order-independent, case-insensitive multiset equality for lists of strings
    (None treated as empty). Used for elliptic curves, key types and URI protocols, which the
    platform may return upper-cased while users typically write them lower-cased.

    :rtype: bool
    """
    remote_counts = Counter(str(x).upper() for x in (remote_values or []))
    local_counts = Counter(str(x).upper() for x in (local_values or []))
    return remote_counts == local_counts


def _check_value(remote_value, local_value):
    """
    Validates if both parameters are equal.

    :param remote_value:
    :param local_value:
    :return: True if both parameters hold the same value, False otherwise
    :rtype: bool
    """
    if isinstance(remote_value, bool) or isinstance(local_value, bool):
        remote_value = False if remote_value is None else remote_value
        local_value = False if local_value is None else local_value
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
    return _check_list_case_insensitive(remote_values, local_values)
