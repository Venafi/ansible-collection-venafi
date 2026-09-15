#!/usr/bin/python
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
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: venafi_policy
short_description: Creates or deletes policies on CyberArk platforms
description:
    - CyberArk policy management module for working with CyberArk Certificate Manager, SaaS,
      CyberArk Certificate Manager, Self-Hosted, and Strata Cloud Manager (NGTS).
    - It allows to create a policy at I(zone) on the CyberArk platform from a file defined by I(policy_spec_path).
    - NGTS (Strata Cloud Manager) is selected by supplying the OAuth2 service-account credentials
      (I(client_id), I(client_secret), and I(tsg_id) or I(scope)). NGTS has no Application or owner
      layer, so the policy's I(users) and I(owners) are ignored and read back empty.
    - As of now, policy's delete operation is not supported.
version_added: "0.6.0"
author: Russel Vela (@rvelaVenafi)
options:
    zone:
        description:
            - The location where the Policy Specification will be created on the CyberArk platform.
            - Self-Hosted (TPP) uses a policy-folder DN (for example C(example\\policy)); SaaS uses
              C(ApplicationName\\IssuingTemplateAlias); NGTS (Strata Cloud Manager) uses the
              issuing-template (CIT) alias only, with no application split.
        required: true
        type: str
    policy_spec_path:
        description:
            - The path in the host of the Policy Specification file.
            - When defined it will be used to create a new Policy in the CyberArk platform located at I(zone).
            - Ignored when I(state=absent).
        default: null
        type: path
seealso:
    - module: venafi.machine_identity.venafi_certificate
extends_documentation_fragment:
    - files
    - venafi.machine_identity.common_options
    - venafi.machine_identity.venafi_connection_options
'''

EXAMPLES = '''
- name: Apply a policy on CyberArk Certificate Manager, Self-Hosted (TPP)
  hosts: localhost
  connection: local
  tasks:
    - name: Create or update the policy folder
      venafi.machine_identity.venafi_policy:
        url: 'https://tpp.example.com/vedsdk'
        access_token: !vault |
            $ANSIBLE_VAULT;1.1;AES256
        zone: 'example\\policy'
        policy_spec_path: '/etc/venafi/policy.json'
        state: present

- name: Apply a policy on CyberArk Certificate Manager, SaaS
  hosts: localhost
  connection: local
  tasks:
    - name: Create or update the issuing template
      venafi.machine_identity.venafi_policy:
        token: !vault |
            $ANSIBLE_VAULT;1.1;AES256
        zone: 'My Application\\My Issuing Template'
        policy_spec_path: '/etc/venafi/policy.yml'
        state: present

- name: Apply a policy on Strata Cloud Manager (NGTS)
  hosts: localhost
  connection: local
  tasks:
    - name: Create or update the issuing template (NGTS uses the CIT alias only)
      venafi.machine_identity.venafi_policy:
        # url and token_url default to the Palo Alto production endpoints; set both
        # explicitly for non-production tenants.
        client_id: 'svc-account@1234567890.iam.panserviceaccount.com'
        client_secret: !vault |
            $ANSIBLE_VAULT;1.1;AES256
        tsg_id: '1234567890'
        zone: 'my-issuing-template'
        policy_spec_path: '/etc/venafi/ngts-policy.yml'
        state: present
'''

RETURN = '''
created:
    description: Name of the policy created at the CyberArk platform. May be empty.
    returned: always
    type: str
    sample: My_App\\my_policy

deleted:
    description: Name of the policy deleted at the CyberArk platform. May be empty.
    returned: always
    type: str
    sample: My_App_to_delete\\my_policy_to_delete

updated:
    description: Name of the policy updated at the CyberArk platform. May be empty.
    returned: always
    type: str
    sample: My_App_to_update\\my_policy_to_update
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native
try:
    from ansible_collections.venafi.machine_identity.plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec, is_ngts_request
    from ansible_collections.venafi.machine_identity.plugins.module_utils.policy_utils \
        import check_policy_specification
except ImportError:
    from plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec, is_ngts_request
    from plugins.module_utils.policy_utils \
        import check_policy_specification

HAS_VCERT = True
try:
    from vcert.errors import VenafiError, VenafiConnectionError, AuthenticationError, ServerUnexptedBehavior
    from vcert.parser import json_parser, yaml_parser
except ImportError:
    HAS_VCERT = False

F_TEST_MODE = 'test_mode'
F_CHANGED = 'changed'
F_CHANGED_MSGS = 'changed_msgs'
F_STATE = 'state'
F_FORCE = 'force'
F_ZONE = 'zone'
F_PS_PATH = 'policy_spec_path'
F_POLICY_CREATED = 'created'
F_POLICY_UPDATED = 'updated'
F_POLICY_DELETED = 'deleted'


class VPolicyManagement:
    def __init__(self, module):
        """
        :param AnsibleModule module: The module containing the necessary parameters to perform the operations
        """
        self.module = module
        self.state = module.params[F_STATE]
        self.force = module.params[F_FORCE]
        self.zone = module.params[F_ZONE]
        self.local_ps = module.params[F_PS_PATH]
        self.connection = get_venafi_connection(module)

    def validate(self):
        """
        Ensures the policy specification resource is in its desired state.
        Otherwise raises an error

        :return: None
        """
        result = self.check()
        if result[F_CHANGED]:
            self.module.fail_json(
                msg=result[F_CHANGED_MSGS]
            )

    def check(self):
        """
        Validates if the resources have changed since the last execution

        :return: a dictionary with the results of the validation
        :rtype: dict[str, Any]
        """
        # The fake/test backend implements no policy operations (get_policy raises
        # NotImplementedError, which is not a VenafiError and would escape as a raw traceback), so
        # fail fast with a clear message instead of crashing.
        if self.module.params.get(F_TEST_MODE):
            self.module.fail_json(msg='Policy management is not supported in test_mode: the fake '
                                      'backend implements no policy operations.')

        result = {
            F_CHANGED: False,
            F_POLICY_CREATED: '',
            F_POLICY_UPDATED: '',
            F_POLICY_DELETED: ''
        }
        msgs = []
        try:
            remote_ps = self.connection.get_policy(self.zone)
        except (VenafiConnectionError, AuthenticationError, ServerUnexptedBehavior) as e:
            # Connection/auth/server errors are not "policy absent". Treating them as a missing
            # policy would mask an NGTS token_url/credential problem as a spurious "creating policy"
            # (changed=True) and defeat idempotency, so surface them instead of swallowing.
            self.module.fail_json(msg='Failed to read policy %s: %s' % (self.zone, to_native(e)))
        except VenafiError as e:
            self.module.debug('Get policy %s failed. Assuming Policy does not exist. Error: %s'
                              % (self.zone, to_native(e)))
            remote_ps = None

        if self.state == 'present':
            if remote_ps:
                # Policy already exists: compare the local spec against the platform's to decide
                # whether an update is actually needed (idempotency). NGTS has no owner/user layer,
                # so skip owners/users/approvers there (they always read back empty).
                local_ps = self._read_policy_spec_file(self.local_ps)
                changed, new_msgs = check_policy_specification(
                    local_ps, remote_ps, ignore_owners_users=is_ngts_request(self.module))
                if changed:
                    result[F_CHANGED] = True
                    result[F_POLICY_UPDATED] = self.zone
                    msgs.extend(new_msgs)
                    msgs.append('Policy %s differs from local file %s. Updating.'
                                % (self.zone, self.local_ps))
                else:
                    msgs.append('No changes detected in local file %s. No action required' % self.local_ps)
            else:
                # Policy does not exist in CyberArk platform, must be created.
                result[F_CHANGED] = True
                result[F_POLICY_CREATED] = self.zone
                msgs.append('Creating policy %s on CyberArk platform' % self.zone)
        elif self.state == 'absent':
            if remote_ps:
                # Policy exists but the desired state is absent. Deletion is not supported by the
                # vcert library, so report the drift honestly; the apply step fails cleanly.
                result[F_CHANGED] = True
                result[F_POLICY_DELETED] = self.zone
                msgs.append('Policy %s exists but deletion is not supported by the vcert library; '
                            'state=absent cannot be satisfied.' % self.zone)
            else:
                # Policy does not exist on CyberArk platform, no action required.
                msgs.append('Policy %s is absent on CyberArk platform. No action required' % self.zone)

        result[F_CHANGED_MSGS] = ' | '.join(msgs)
        return result

    def _read_policy_spec_file(self, ps_filename):
        """
        Reads the content of the given file and parses it to a vcert.policy.PolicySpecification object
        that CyberArk can use to create policies

        :param str ps_filename: The path of the vcert.policy.PolicySpecification file to read
        :rtype: vcert.policy.PolicySpecification
        """
        parser = _get_policy_spec_parser(ps_filename)
        ps = parser.parse_file(ps_filename) if parser else None
        if not ps:
            self.module.fail_json(msg='Unknown file. Could not read data from %s' % ps_filename)

        return ps

    def validate_local_path(self):
        """
        Validates that the path defined by local_ps exists.

        :return: True if path exists, False otherwise
        :rtype: bool
        """
        if not self.local_ps:
            self.module.fail_json(msg='%s field not defined' % F_PS_PATH)
        if not os.path.exists(self.local_ps):
            self.module.fail_json(msg="File at %s does not exist" % self.local_ps)
        return True

    def set_policy(self):
        """
        Reads the content of the source vcert.policy.PolicySpecification and creates a policy in CyberArk
        with the zone as name

        :return: Nothing
        """
        local_ps = self._read_policy_spec_file(self.local_ps)
        if local_ps:
            try:
                self.connection.set_policy(self.zone, local_ps)
            except Exception as e:
                self.module.fail_json('Failed to set policy at %s. Error: %s' % (self.zone, to_native(e)))
        else:
            self.module.fail_json(msg='Could not get a parser for the file %s. Unknown extension' % self.local_ps)

    def delete_policy(self):
        """
        Deletes the given policy on the CyberArk platform
        :return: Nothing
        """
        self.module.fail_json(msg='Delete policy operation not supported by vcert python library')


def _get_policy_spec_parser(ps_filename):
    """
    Returns the specific parser for a given file based on the file extension.
    Only supports json and yaml/yml files

    :param ps_filename: the path of the file to be read by the parser
    :return: a parser implementation
    :rtype: json_parser or yaml_parser
    """
    path_tuple = os.path.splitext(ps_filename)
    if path_tuple[1] == '.json':
        return json_parser
    elif path_tuple[1] in ('.yaml', '.yml'):
        return yaml_parser

    return None


def main():
    # define the available arguments/parameters that a user can pass to the module
    args = module_common_argument_spec()
    args.update(venafi_common_argument_spec())
    args.update(
        # Policy Management
        zone=dict(type='str', required=True),
        path=dict(type='path', aliases=['policy_spec_path'])
    )
    module = AnsibleModule(
        argument_spec=args,
        supports_check_mode=True,
        add_file_common_args=True,
    )
    if not HAS_VCERT:
        module.fail_json(msg='\'vcert\' python library is required')

    vcert = VPolicyManagement(module)
    # policy_spec_path is only used for state=present; it is ignored for state=absent
    # (documented), so only require the file to exist when creating/updating a policy.
    if vcert.state == 'present':
        vcert.validate_local_path()

    check_result = vcert.check()
    if module.check_mode:
        module.exit_json(**check_result)

    if vcert.state == 'present' and (check_result[F_CHANGED] or vcert.force):
        vcert.set_policy()
    elif vcert.state == 'absent' and check_result[F_CHANGED]:
        # delete_policy() is not supported by the vcert library and fails cleanly. Only reached
        # when the policy actually exists (check_result changed) so 'force' cannot trigger a
        # spurious delete of a non-existent policy.
        vcert.delete_policy()

    module.exit_json(**check_result)


if __name__ == '__main__':
    main()
