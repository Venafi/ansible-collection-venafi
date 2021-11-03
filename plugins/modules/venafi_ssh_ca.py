#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2019 Venafi, Inc.
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
from __future__ import absolute_import, print_function, unicode_literals

DOCUMENTATION = """
---
module: venafi_ssh_ca
short_description: Retrieves SSH Certificate Authority public key data and principals from Venafi TPP.
description:
    - This is the Venafi SSH Certificate Authority module for working with Venafi Trust Protection Platform.
    - It allows to retrieve the public key and default principals from a given Certificate Authority.
version_added: "0.7.5"
author: Russel Vela (@rvelaVenafi)
options:
    ca_template:        
        description:
            - The name of the Certificate Authority from whom the public key and principals is retrieved.
        required: true if I(ca_guid) option not passed. 
        type: str
    ca_guid:
        description:
            - The global unique identifier of the Certificate Authority from whom the public key is retrieved.
        required: true if I(ca_template) option not passed.
        type: str
    public_key_path:
        description:
            - The path where the public key is going to be stored in the remote host.
        required: true
        type: path
extends_documentation_fragment:
    - files
    - venafi.machine_identity.common_options
"""

EXAMPLES = """
# Retrieve CA public key data only
---
- name: "retrieve_ssh_ca_public_key_default"
  venafi.machine_identity.venafi_ssh_ca:
    url: "https://venafi.example.com"
    ca_template: "my-ssh-cit"
    public_key_path: "/temp/etc/ssh/ca/my_ca_public_key.pub"
  register: ca_out
- name: "dump output"
  debug:
    msg: "{{ ca_out }}"
    
# Retrieve CA public key data and principals using user/password
---
- name: "retrieve_ssh_ca_public_key_and_principals"
  venafi.machine_identity.venafi_ssh_ca:
    url: "https://venafi.example.com"
    user: "my_user"
    password: "my_password"
    ca_template: "my-ssh-cit"
    public_key_path: "/temp/etc/ssh/ca/my_ca_public_key.pub"
  register: ca_out
- name: "dump output"
  debug:
    msg: "{{ ca_out }}"
    
# Retrieve CA public key data and principals using access token
---
- name: "retrieve_ssh_ca_public_key_and_principals"
  venafi.machine_identity.venafi_ssh_ca:
    url: "https://venafi.example.com"
    access_token: "my4cce55+t0k3n=="
    ca_template: "my-ssh-cit"
    public_key_path: "/temp/etc/ssh/ca/my_ca_public_key.pub"
  register: ca_out
- name: "dump output"
  debug:
    msg: "{{ ca_out }}"
"""

RETURN = """
ssh_ca_public_key_filename:
    description: Path to the Certificate Authority public key file.
    returned: when I(state) is C(present)
    type: str
    sample: "/etc/ssh/ca/venafi.example.pub"

ssh_ca_public_key:
    description: Certificate Authority Public Key data in string format.
    returned: when I(state) is C(present)
    type: str
    sample: "ssh-rsa AAAAB3NzaC1yc2E...ZZOQ== my-cit-name-here"
 
ssh_ca_principals:
    description: Default principals of the given Certificate Authority.
    returned: when I(state) is C(present) and Venafi credentials are provided to the module
    type: list
    sample: ["bob", "alice", "luis", "melissa"]

ssh_ca_public_key_removed:
    description: Path of the removed public key file.
    returned: when I(state) is C(absent)
    type: str
    sample: "/etc/ssh/venafi.example.pub"
"""

import os

from ansible.module_utils.basic import AnsibleModule
try:
    from ansible_collections.venafi.machine_identity.plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec, F_STATE, F_FORCE, \
        F_STATE_PRESENT, F_STATE_ABSENT, F_USER, F_PASSWORD, get_access_token
except ImportError:
    from plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec, F_STATE, F_FORCE, \
        F_STATE_PRESENT, F_STATE_ABSENT, F_USER, F_PASSWORD, get_access_token

HAS_VCERT = True
try:
    from vcert import CommonConnection, SSHCertRequest, SSHKeyPair, SCOPE_SSH, SSHConfig, VenafiPlatform
    from vcert.ssh_utils import SSHRetrieveResponse, SSHCATemplateRequest
except ImportError:
    HAS_VCERT = False

F_CA_TEMPLATE = 'ca_template'
F_CA_GUID = 'ca_guid'
F_PUB_KEY_FILE_EXISTS = 'public_key_file_exists'
F_CHANGED = 'changed'
F_CHANGED_MSG = 'changed_msg'

F_PUBLIC_KEY_DIR = 'public_key_path'
F_WINDOWS_CERT = 'windows_cert'

CA_PUB_KEY_STR = "%s/%s.pub"


class VSSHCertAuthority:
    def __init__(self, module):
        """
        :param AnsibleModule module:
        """
        self.module = module  # type: AnsibleModule
        self.connector = get_venafi_connection(module, platform=VenafiPlatform.TPP)  # type: CommonConnection
        self.state = module.params[F_STATE]  # type: str
        self.force = module.params[F_FORCE]  # type: bool
        # SSH CA attributes
        self.ca_template = module.params[F_CA_TEMPLATE]  # type: str
        self.ca_guid = module.params[F_CA_GUID]  # type: str
        # SSH file attributes
        self.ca_public_key_path = module.params[F_PUBLIC_KEY_DIR]  # type: str

        user = module.params[F_USER]
        password = module.params[F_PASSWORD]
        if user and password:
            get_access_token(connector=self.connector, user=user, password=password, scope=SCOPE_SSH)

        self.changed = False
        self.ca_principals = None
        self.ca_public_key = None

    def check(self):
        """
        Validates if the resources have changed since the last execution

        :return: a dictionary with the results of the validation
        :rtype: dict[Any, Any]
        """
        result = dict()

        public_key_file_exists = False
        if self.ca_public_key_path and os.path.exists(self.ca_public_key_path):
            public_key_file_exists = True

        if self.state == F_STATE_PRESENT:
            if public_key_file_exists:
                result = {
                    F_PUB_KEY_FILE_EXISTS: True,
                    F_CHANGED: False,
                    F_CHANGED_MSG: "SSH CA Public Key found. No action required."
                }
            else:
                result = {
                    F_PUB_KEY_FILE_EXISTS: False,
                    F_CHANGED: True,
                    F_CHANGED_MSG: "No SSH CA Public Key file found. Retrieving from Venafi platform.",
                }
        elif self.state == F_STATE_ABSENT:
            if public_key_file_exists:
                # If CA public key exists, it must be deleted from host
                result = {
                    F_PUB_KEY_FILE_EXISTS: True,
                    F_CHANGED: True,
                    F_CHANGED_MSG: "SSH CA Public Key found. Deleting it from host."
                }
            else:
                # If CA Public Key does not exist, no change is required.
                result = {
                    F_PUB_KEY_FILE_EXISTS: False,
                    F_CHANGED: False,
                    F_CHANGED_MSG: "SSH CA Public Key not found. No action required."
                }
        return result

    def directory_exist(self):
        public_key_dir = os.path.dirname(self.ca_public_key_path or "/a")

        if os.path.isdir(public_key_dir):
            return True
        elif os.path.exists(public_key_dir):
            self.module.fail_json(msg="Path %s already exists but is not a directory." % public_key_dir)
        elif not os.path.exists(public_key_dir):
            self.module.fail_json(msg="Path %s does not exist." % public_key_dir)
        else:
            return False

    def retrieve_ssh_config(self):
        request = SSHCATemplateRequest(ca_template=self.ca_template, ca_guid=self.ca_guid)
        response = self.connector.retrieve_ssh_config(ca_request=request)
        self._write_response(response=response)
        self.changed = True
        self.ca_public_key = response.ca_public_key
        self.ca_principals = response.ca_principals

    def _write_response(self, response):
        """

        :param SSHConfig response:
        :rtype: None
        """
        public_key_data = response.ca_public_key
        if public_key_data:
            with open(self.ca_public_key_path, "wb") as public_key_file:
                public_key_file.write(public_key_data.encode())

    def delete_ssh_config(self):
        if os.path.exists(self.ca_public_key_path):
            os.remove(self.ca_public_key_path)
            self.changed = True

    def validate(self):
        """
        Ensures the resource is in its desired state.
        Otherwise raises an error

        :return: None
        """
        result = self.check()
        if result[F_CHANGED]:
            self.module.fail_json(
                msg="Operation validation failed. No changes should be found after execution. Found: %s"
                    % result[F_CHANGED_MSG])
        return result

    def dump(self):
        result = {
            'changed': self.changed,
        }
        if self.state == "present":
            result['ssh_ca_public_key_filename'] = self.ca_public_key_path
            result['ssh_ca_public_key'] = self.ca_public_key
            result['ssh_ca_principals'] = self.ca_principals
        else:
            result['ssh_ca_public_key_removed'] = self.ca_public_key_path

        return result


def main():
    args = module_common_argument_spec()
    args.update(venafi_common_argument_spec())
    args.update(
        # SSH Certificate Authority attributes
        ca_template=dict(type='str', required=False),
        ca_guid=dict(type='str', required=False),
        public_key_path=dict(type='path', required=True),
    )
    module = AnsibleModule(
        # define the available arguments/parameters that a user can pass to the module
        argument_spec=args,
        supports_check_mode=True,
        add_file_common_args=True,
    )
    if not HAS_VCERT:
        module.fail_json(msg='"vcert" python library is required')

    vcert = VSSHCertAuthority(module)
    check_result = vcert.check()
    if module.check_mode:
        module.exit_json(**check_result)

    if vcert.state == F_STATE_PRESENT and (check_result[F_CHANGED] or vcert.force):
        if not vcert.directory_exist():
            module.fail_json(msg="CA Public Key directory does not exist.")
        vcert.retrieve_ssh_config()
    elif vcert.state == F_STATE_ABSENT and (check_result[F_CHANGED] or vcert.force):
        # delete CA public key
        vcert.delete_ssh_config()

    vcert.validate()
    result = vcert.dump()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
