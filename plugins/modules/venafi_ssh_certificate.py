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

import os

from ansible.module_utils.basic import AnsibleModule
try:
    from ansible_collections.venafi.machine_identity.plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec
except ImportError:
    from plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec

HAS_VCERT = HAS_CRYPTOGRAPHY = True
try:
    from vcert import CommonConnection, SSHCertRequest, SSHKeyPair, write_ssh_files
    from vcert.ssh_utils import SSHRetrieveResponse
except ImportError:
    HAS_VCERT = False
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import serialization
except ImportError:
    HAS_CRYPTOGRAPHY = False


MSG_CERT_FILE_NOT_FOUND = "SSH Certificate file does not exist"
SSH_GEN_TYPE_PROVIDED = 'provided'
SSH_GEN_TYPE_LOCAL = 'local'
SSH_GEN_TYPE_SERVICE = 'service'

F_CERT_FILE_EXISTS = 'cert_file_exists'
F_CHANGED = 'changed'
F_CHANGED_MSG = 'changed_msg'

F_STATE = 'state'
F_FORCE = 'force'

F_CERT_PATH = 'cert_path'
F_PRIVATE_KEY_PATH = 'private_key_path'
F_PUBLIC_KEY_PATH = 'public_key_path'
F_WINDOWS_CERT = 'windows_cert'

F_SSH_KEY_GEN_TYPE = 'ssh_key_generation_type'
F_PRIVATE_KEY_PASS = 'private_key_passphrase'
F_SSH_KEY_SIZE = 'ssh_key_size'
F_CADN = 'cadn'
F_KEY_ID = 'key_id'
F_VALIDITY_PERIOD = 'validity_period'
F_POLICY_DN = 'policy_dn'
F_OBJECT_NAME = 'object_name'
F_DEST_ADDRESSES = 'destination_addresses'
F_PRINCIPALS = 'principals'
F_EXTENSIONS = 'extensions'
F_FORCE_COMMAND = 'force_command'
F_SRC_ADDRESSES = 'source_addresses'


class VSSHCertificate:
    def __init__(self, module):
        """
        :param AnsibleModule module:
        """
        self.module = module  # type: AnsibleModule
        self.connection = get_venafi_connection(module)  # type: CommonConnection
        self.state = module.params[F_STATE]  # type: str
        self.force = module.params[F_FORCE]  # type: bool
        # SSH keypair attributes
        self.ssh_key_generation_type = module.params[F_SSH_KEY_GEN_TYPE]  # type: str
        self.private_key_passphrase = module.params[F_PRIVATE_KEY_PASS]  # type: str
        self.ssh_key_size = module.params[F_SSH_KEY_SIZE]  # type: int
        # SSH Certificate attributes
        self.cadn = module.params[F_CADN]  # type: str
        self.key_id = module.params[F_KEY_ID]   # type: str
        self.validity_period = module.params[F_VALIDITY_PERIOD]   # type: str
        self.policy_dn = module.params[F_POLICY_DN]   # type: str
        self.object_name = module.params[F_OBJECT_NAME]   # type: str
        self.destination_addresses = module.params[F_DEST_ADDRESSES]   # type: list
        self.principals = module.params[F_PRINCIPALS]   # type: list
        self.extensions = module.params[F_EXTENSIONS]   # type: list
        self.force_command = module.params[F_FORCE_COMMAND]   # type: str
        self.source_addresses = module.params[F_SRC_ADDRESSES]   # type: list
        # SSH files attributes
        self.certificate_filename = module.params[F_CERT_PATH]  # type: str
        self.public_key_filename = module.params[F_PUBLIC_KEY_PATH]  # type: str
        self.private_key_filename = module.params[F_PRIVATE_KEY_PATH]  # type: str
        self.windows_cert = module.params[F_WINDOWS_CERT]  # type: bool

    def check(self):
        """
        Validates if the resources have changed since the last execution

        :return: a dictionary with the results of the validation
        :rtype: dict[Any, Any]
        """
        result = dict()

        cert_file_exists = False
        if os.path.exists(self.certificate_filename):
            cert_file_exists = True
        if self.state == 'present':
            # Validate that a public key file has been passed when key generation is "provided"
            if self.ssh_key_generation_type == SSH_GEN_TYPE_PROVIDED:
                if not os.path.exists(self.public_key_filename):
                    self.module.fail_json(msg="File not found. "
                                              "[%s] field is required when SSH key generation type is [%s]."
                                              % (F_PUBLIC_KEY_PATH, SSH_GEN_TYPE_PROVIDED))
            # TODO: For now we are not validating the scenario when files are already present.
            # else:
            #     # Regardless of generation type being local or service,
            #     # it should fail if the public/private key files already exist
            #     fail = False
            #     fail_msg = "SSH %s key file already exists at [%s]. [%s] field is used to save the generated key when" \
            #                " SSH key generation type is set to '%s'."
            #     if os.path.exists(self.public_key_filename):
            #         fail = True
            #         fail_msg = fail_msg % ("public", self.public_key_filename, F_PUBLIC_KEY_PATH,
            #                                self.ssh_key_generation_type)
            #     elif os.path.exists(self.private_key_filename):
            #         fail = True
            #         fail_msg = fail_msg % ("private", self.private_key_filename, F_PRIVATE_KEY_PATH,
            #                                self.ssh_key_generation_type)
            #     if fail:
            #         self.module.fail_json(msg=fail_msg)
            if cert_file_exists:
                # TODO: what should we check here? How to read the SSH cert to extract info?
                result = {
                    F_CERT_FILE_EXISTS: True,
                    F_CHANGED: True,
                    F_CHANGED_MSG: "Mockup message when the certificate is different from what already exists.",
                }
            else:
                result = {
                    F_CERT_FILE_EXISTS: False,
                    F_CHANGED: True,
                    F_CHANGED_MSG: MSG_CERT_FILE_NOT_FOUND,
                }
        elif self.state == 'absent':
            if cert_file_exists:
                # If cert exists, it must be revoked/deleted from host
                # TODO: vcert-python does not support revoking an SSH certificate as of now
                result = {
                    F_CERT_FILE_EXISTS: True,
                    F_CHANGED: True,
                    F_CHANGED_MSG: "SSH Certificate found. Deleting it from host."
                }
            else:
                # If cert does not exist, no change is required.
                result = {
                    F_CERT_FILE_EXISTS: False,
                    F_CHANGED: False,
                    F_CHANGED_MSG: "SSH certificate not found. No action required."
                }
        return result

    def validate(self):
        """
        Ensures the policy specification resource is in its desired state.
        Otherwise raises an error

        :return: None
        """
        result = self.check()
        if result[F_CHANGED]:
            self.module.fail_json(
                msg="Operation validation failed. No changes should be found after execution. Found: %s"
                    % result[F_CHANGED_MSG])

    def enroll(self):
        ssh_request = SSHCertRequest(
            cadn=self.cadn,
            key_id=self.key_id,
            validity_period=self.validity_period,
            policy_dn=self.policy_dn,
            object_name=self.object_name,
            destination_addresses=self.destination_addresses,
            principals=self.principals,
            extensions=self.extensions,
            force_command=self.force_command,
            source_addresses=self.source_addresses
        )

        if self.ssh_key_generation_type == SSH_GEN_TYPE_PROVIDED:
            with open(self.public_key_filename, 'r') as pub_key:
                data = pub_key.read()
                ssh_request.set_public_key_data(data)
        elif self.ssh_key_generation_type == SSH_GEN_TYPE_LOCAL:
            ssh_kp = SSHKeyPair()
            ssh_kp.generate(key_size=self.ssh_key_size, passphrase=self.private_key_passphrase)
            ssh_request.set_public_key_data(ssh_kp.public_key())

        success = self.connection.request_ssh_cert(ssh_request)
        if not success:
            self.module.fail_json(msg="Failed to request certificate with key id %s" % ssh_request.key_id)

        response = self.connection.retrieve_ssh_cert(ssh_request)
        if response:
            self._write_response(response)

    def _write_response(self, response):
        """
        :param SSHRetrieveResponse response:
        :rtype: None
        """
        cert_data = response.certificate_data
        private_key_data = None
        public_key_data = None
        if self.ssh_key_generation_type is not SSH_GEN_TYPE_PROVIDED:
            private_key_data = response.private_key_data
            public_key_data = response.public_key_data

        with open(self.certificate_filename, "wb") as cert_file:
            cert_file.write(cert_data.encode())

        if private_key_data:
            if not self.windows_cert:
                private_key_data = private_key_data.replace("\r\n", "\n")
            with open(self.private_key_filename, "wb") as private_key_file:
                private_key_file.write(private_key_data.encode())

        if public_key_data:
            with open(self.public_key_filename, "wb") as public_key_file:
                public_key_file.write(public_key_data.encode())

    def revoke(self):
        self.module.fail_json(msg='SSH certificate revoke operation not supported by vcert library')

    def directory_exist(self):
        cert_dir = os.path.dirname(self.certificate_filename or "/a")
        private_key_dir = os.path.dirname(self.private_key_filename or "/a")
        public_key_dir = os.path.dirname(self.public_key_filename or "/a")
        ok = True
        for p in {cert_dir, private_key_dir, public_key_dir}:
            if os.path.isdir(p):
                continue
            elif os.path.exists(p):
                self.module.fail_json(msg="Path %s already exists but is not a directory." % p)
                ok = False
            elif not os.path.exists(p):
                self.module.fail_json(msg="Path %s does not exist." % p)
                ok = False
            else:
                ok = False
        return ok


def main():
    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    args = module_common_argument_spec()
    args.update(venafi_common_argument_spec())
    args.update(
        # SSH files attributes
        path=dict(type='path', aliases=['cert_path'], required=True),
        public_key_path=dict(type='path', required=False),
        private_key_path=dict(type='path', required=False),
        # SSH KeyPair attributes
        ssh_key_generation_type=dict(type='str',
                                     choices=[SSH_GEN_TYPE_PROVIDED, SSH_GEN_TYPE_LOCAL, SSH_GEN_TYPE_SERVICE],
                                     default=SSH_GEN_TYPE_PROVIDED),
        private_key_passphrase=dict(type='str', no_log=True),
        ssh_key_size=dict(type='int', choices=[1024, 2048, 3072, 4096], default=3072, required=False),
        # SSH Certificate attributes
        cadn=dict(type='str', required=True),
        key_id=dict(type='str', required=True),
        validity_period=dict(type='str', required=False),
        policy_dn=dict(type='str', required=False),
        object_name=dict(type='str', required=False),
        destination_addresses=dict(type='list', elements='str', required=False),
        principals=dict(type='list', elements='str', required=False),
        extensions=dict(type='list', elements='str', required=False),
        force_command=dict(type='str', required=False),
        source_addresses=dict(type='list', elements='str', required=False),
        windows_cert=dict(type='bool', default=False, required=False)
    )
    module = AnsibleModule(
        # define the available arguments/parameters that a user can pass to the module
        argument_spec=args,
        supports_check_mode=True,
        add_file_common_args=True,
    )

    if not HAS_VCERT:
        module.fail_json(msg='"vcert" python library is required')
    if not HAS_CRYPTOGRAPHY:
        module.fail_json(msg='"cryptography" python library is required')

    vcert = VSSHCertificate(module)
    check_result = vcert.check()
    if module.check_mode:
        module.exit_json(**check_result)

    if vcert.state == 'present' and (check_result[F_CHANGED] or vcert.force):
        if not vcert.directory_exist():
            module.fail_json(msg="One or more directory do not exist.")
        vcert.enroll()
    elif vcert.state == 'absent' and (check_result[F_CHANGED] or vcert.force):
        # revoke/delete cert here
        vcert.revoke()

    vcert.validate()
    module.exit_json(**check_result)


if __name__ == '__main__':
    main()
