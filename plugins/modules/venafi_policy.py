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
ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: venafi_policy
short_description: Creates or deletes policies on Venafi platforms
version_added: '1.0.0'
description:
    - This is the Venafi policy management module for working with Venafi as a Service (VaaS)
      or Venafi Trusted Protection Platform (TPP).
    - It allows to create a policy at I(zone) on the Venafi platform
      from a file defined by I(policy_spec_path).
    - As of now, policy's delete operation is not supported.
options:
    zone:
        description:
            - The location where the Policy Specification will be created on the Venafi platform
        required: true
        type: str

    policy_spec_path:
        description:
            - The path in the host of the Policy Specification file.
            - When defined it will be used to create a new Policy in the Venafi platform located at I(zone).
            - Ignored when I(state=absent).
        type: path
extends_documentation_fragment:
    - files
    - community.venafi.venafi_connection_options
    - community.venafi.common_options
author:
    - Russel Vela (@rvelaVenafi) on behalf of Venafi Inc.
seealso:
    - module: venafi.machine_identity.venafi_certificate
'''

EXAMPLES = '''
- name: Create a Policy in VaaS

- name: Create a Policy in Venafi TPP
'''

RETURN = '''
policy_created:
    description: Name of the policy created at the Venafi platform.
    returned: always
    type: str
    sample: My_App\\my_policy

policy_deleted:
    description: Name of the policy deleted at the Venafi platform.
    returned: always
    type: str
    sample: My_App_to_delete\\my_policy_to_delete
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
try:
    from ansible_collections.community.venafi.plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec
    from ansible_collections.community.venafi.plugins.module_utils.policy_utils \
        import check_policy_specification
except ImportError:
    from plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec
    from plugins.module_utils.policy_utils import check_policy_specification

HAS_VCERT = True
try:
    from vcert.errors import VenafiConnectionError
    from vcert.parser import json_parser, yaml_parser
    from vcert.policy import PolicySpecification
except ImportError:
    HAS_VCERT = False

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
        result = {
            F_CHANGED: False,
            F_POLICY_CREATED: '',
            F_POLICY_UPDATED: '',
            F_POLICY_DELETED: ''
        }
        msgs = []
        try:
            remote_ps = self.connection.get_policy(self.zone)
        except VenafiConnectionError as e:
            self.module.debug('Get policy %s failed. Assuming Policy does not exist. Error: %s'
                              % (self.zone, to_native(e)))
            remote_ps = None

        if self.state == 'present':
            if remote_ps:
                # Policy already exists in Venafi platform
                # Validate that both, the source policy and the Venafi platform policy have the same content
                local_ps = self._read_policy_spec_file(self.local_ps)
                changed, new_msgs = check_policy_specification(local_ps, remote_ps)
                if changed:
                    result[F_CHANGED] = True
                    result[F_POLICY_UPDATED] = self.zone
                    msgs.extend(new_msgs)
                    msgs.append('Changes detected in local file %s. Updating policy %s on Venafi platform'
                                % (self.local_ps, self.zone))
                else:
                    msgs.append('No changes detected in local file %s. No action required' % self.local_ps)
            else:
                # Policy does not exist in Venafi platform, must be created.
                result[F_CHANGED] = True
                result[F_POLICY_CREATED] = self.zone
                msgs.append('Creating policy %s on Venafi platform' % self.zone)
        elif self.state == 'absent':
            if remote_ps:
                # Policy already exists in Venafi platform, must be deleted.
                result[F_CHANGED] = True
                result[F_POLICY_DELETED] = self.zone
                msgs.append('Deleting %s policy from Venafi platform' % self.zone)
            else:
                # Policy does not exist on Venafi platform, no action required.
                msgs.append('Policy %s is absent on Venafi platform. No action required' % self.zone)

        result[F_CHANGED_MSGS] = ' | '.join(msgs)
        return result

    def _read_policy_spec_file(self, ps_filename):
        """
        Reads the content of the given file and parses it to a PolicySpecification object
        that Venafi can use to create policies

        :param str ps_filename: The path of the PolicySpecification file to read
        :rtype: PolicySpecification
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
        Reads the content of the source PolicySpecification and creates a policy in Venafi
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
        Deletes the given policy on the Venafi platform
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
    # Validate that policy_spec_path exists
    vcert.validate_local_path()

    check_result = vcert.check()
    if module.check_mode:
        module.exit_json(**check_result)

    if vcert.state == 'present' and (check_result[F_CHANGED] or vcert.force):
        vcert.set_policy()
    elif vcert.state == 'absent' and (check_result[F_CHANGED] or vcert.force):
        # TODO create delete_policy() method. Not yet available on vcert python library
        vcert.delete_policy()

    vcert.validate()
    module.exit_json(**check_result)


if __name__ == '__main__':
    main()
