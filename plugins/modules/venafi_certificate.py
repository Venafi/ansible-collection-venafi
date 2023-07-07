#!/usr/bin/python
#
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
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: venafi_certificate
short_description: Venafi certificate module for working with Venafi as a Service or Venafi Trust Protection Platform
description:
    - Venafi certificate module for working with Venafi as a Service (VaaS) or Trust Protection Platform (TPP).
version_added: "0.6.0"
author: Alexander Rykalin (@arykalin)
options:
    alt_name:
        description:
            - SAN extension to attach to the certificate signing request
            - This can either be a 'comma separated string' or a YAML list.
            - Values should be prefixed by their options. (IP:,email:,DNS:).
        default: null
        type: list
        elements: str
        aliases:
            - subjectAltName
    before_expired_hours:
        description:
            - If certificate will expire in less hours than this value, module will try to renew it.
        default: 72
        type: int
    cert_path:
        description:
            - Remote absolute path where the generated certificate file should be created or is already located.
        required: true
        type: path
    chain_option:
        description:
            - Specify ordering certificates in chain.
        default: last
        choices:
            - first
            - last
        type: str
    chain_path:
        description:
            - Remote absolute path where the generated certificate chain file should be created or is already located.
            - If set certificate and chain will be in separated files.
        default: null
        type: path
    common_name:
        description:
            - CommonName field of the certificate signing request subject.
        required: true
        type: str
        aliases:
            - CN
            - commonName
    csr_origin:
        description:
            - Indicates the source of the CSR used for a certificate request.
            - C(provided) - The CSR at I(csr_path) will be used to request a new certificate.
            - C(local) - The CSR will be generated locally using the values provided through I(privatekey_x) fields.
            - C(service) - The CSR will be generated on the service side (TPP or VaaS).
        required: false
        default: local
        choices:
            - provided
            - local
            - service
        type: str
    csr_path:
        description:
            - Path to the Certificate Signing Request to use when requesting a new certificate.
            - This field is required when I(csr_origin) is C(provided).
        required: false
        default: null
        type: path
    custom_fields:
        description:
            - A key-value map of customer-defined attributes for the certificate.
        default: null
        type: dict
    issuer_hint:
        description:
            - Issuer of the certificate. Ignored when platform is not TPP.
            - Use in combination with I(validity_hours) to specify the validity period of a certificate on TPP.
        default: DEFAULT
        choices:
            - DEFAULT
            - DIGICERT
            - ENTRUST
            - MICROSOFT
        type: str
    privatekey_curve:
        description:
            - Curve name for ECDSA algorithm.
        default: P521
        choices:
            - P256
            - P384
            - P521
        type: str
    privatekey_passphrase:
        description:
            - The passphrase for the privatekey.
        default: null
        type: str
    privatekey_path:
        description:
            - Path to the private key to use when signing the certificate signing request.
            - If not set, the private key will be placed near certificate with key suffix.
        default: null
        type: path
    privatekey_reuse:
        description:
            - If set to false new key won't be generated.
        default: true
        type: bool
    privatekey_size:
        description:
            - Size (in bits) of the TLS/SSL key to generate. Used only for RSA.
        default: 2048
        choices:
            - 2048
            - 3072
            - 4096
            - 8192
        type: int
    privatekey_type:
        description:
            - Type of private key.
        default: RSA
        choices:
            - RSA
            - ECDSA
        type: str
    renew:
        description:
            - Try to renew certificate if is existing but not valid.
        default: true
        type: bool
    use_pkcs12_format:
        description:
            - Use PKCS12 format to serialize the certificate.
        default: false
        type: bool
    validity_hours:
        description:
            - Indicates the validity period of the certificate before it expires.
            - When the platform is TPP, an issuer can be defined as well. See I(issuer_hint).
        required: false
        default: null
        type: int
    zone:
        description:
            - The location of the certificate on the Venafi platform.
        required: true
        type: str
extends_documentation_fragment:
    - files
    - venafi.machine_identity.common_options
    - venafi.machine_identity.venafi_connection_options
'''

EXAMPLES = '''
# Enroll fake certificate for testing purposes
- name: venafi_certificate_fake
  connection: local
  hosts: localhost
  tags:
    - fake
  tasks:
  - name: venafi_certificate
    venafi_certificate:
      test_mode: true
      common_name: 'testcert-fake-{{ 99999999 | random }}.example.com'
      alt_name: 'DNS:www.venafi.example,DNS:m.venafi.example'
      cert_path: '/tmp'
    register: certout
  - name: dump test output
    debug:
      msg: '{{ certout }}'

# Enroll Platform certificate with a lot of alt names
- name: venafi_certificate_tpp
  connection: local
  hosts: localhost
  tags:
    - tpp
  tasks:
  - name: venafi_certificate
    venafi_certificate:
      url: 'https://venafi.example.com/vedsdk'
      user: 'admin'
      password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
      zone: 'example\\\\policy'
      cert_path: '/tmp'
      common_name: 'testcert-tpp-{{ 99999999 | random }}.example.com'
      alt_name: |
        IP:192.168.1.1,DNS:www.venafi.example.com,
        DNS:m.venafi.example.com,email:test@venafi.com,IP Address:192.168.2.2
    register: certout
  - name: dump test output
    debug:
      msg: '{{ certout }}'

# Enroll Cloud certificate
- name: venafi_certificate_cloud
  connection: local
  hosts: localhost
  tags:
    - cloud
  tasks:
  - name: venafi_certificate
    venafi_certificate:
      token: !vault |
          $ANSIBLE_VAULT;1.1;AES256
      zone: 'Default'
      cert_path: '/tmp'
      common_name: 'testcert-cloud.example.com'
    register: certout
  - name: dump test output
    debug:
      msg: '{{ certout }}'
'''

RETURN = '''
privatekey_filename:
    description: Path to the TLS/SSL private key the CSR was generated for.
    returned: changed or success
    type: string
    sample: /etc/ssl/private/venafi.example.pem

privatekey_size:
    description: Size (in bits) of the TLS/SSL private key.
    returned: changed or success
    type: int
    sample: 4096

privatekey_curve:
    description: ECDSA curve of generated private key. Variants are "P521", "P384", "P256", "P224".
    returned: changed or success
    type: string
    sample: "P521"

privatekey_type:
    description: Algorithm used to generate the TLS/SSL private key. Variants are RSA or ECDSA.
    returned: changed or success
    type: string
    sample: RSA

certificate_filename:
    description: Path to the signed certificate.
    returned: changed or success
    type: string
    sample: /etc/ssl/www.venafi.example.pem

chain_filename:
    description: Path to the chain of CA certificates that link the certificate to a trust anchor.
    returned: changed or success
    type: string
    sample: /etc/ssl/www.venafi.example_chain.pem
'''

import datetime
import os.path
import random

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_text
try:
    from ansible_collections.venafi.machine_identity.plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec, get_issuer_hint, \
        DEFAULT, DIGICERT, ENTRUST, MICROSOFT
except ImportError:
    from plugins.module_utils.common_utils \
        import get_venafi_connection, module_common_argument_spec, venafi_common_argument_spec, get_issuer_hint, \
        DEFAULT, DIGICERT, ENTRUST, MICROSOFT

HAS_VCERT = HAS_CRYPTOGRAPHY = True
try:
    from vcert import CertificateRequest, KeyType, CSR_ORIGIN_LOCAL, CSR_ORIGIN_SERVICE, CSR_ORIGIN_PROVIDED, CustomField
except ImportError:
    HAS_VCERT = False
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Some strings variables
STRING_FAILED_TO_CHECK_CERT_VALIDITY = "Certificate is not yet valid, has expired, " \
                                       "or has CN or SANs that differ from the request"
STRING_PKEY_NOT_MATCHED = "Private key does not match certificate public key"
STRING_BAD_PKEY = "Private key file does not contain a valid private key"
STRING_CERT_FILE_NOT_EXISTS = "Certificate file does not exist"
STRING_BAD_PERMISSIONS = "Insufficient file permissions"

F_ZONE = "zone"
F_CERT_PATH = "cert_path"
F_CHAIN_PATH = "chain_path"
F_PK_PATH = "privatekey_path"
F_PK_TYPE = "privatekey_type"
F_PK_SIZE = "privatekey_size"
F_PK_CURVE = "privatekey_curve"
F_PK_PASSPHRASE = "privatekey_passphrase"
F_PK_REUSE = "privatekey_reuse"
F_ALT_NAMES = "alt_name"
F_CN = "common_name"
F_CHAIN_OPTION = "chain_option"
F_CSR_PATH = "csr_path"
F_CSR_ORIGIN = "csr_origin"
F_B4_EXPIRED_HOURS = "before_expired_hours"
F_RENEW = "renew"
F_USE_PKCS12 = "use_pkcs12_format"
F_VALIDITY_HOURS = "validity_hours"
F_ISSUER_HINT = "issuer_hint"
F_CUSTOM_FIELDS = "custom_fields"


class VCertificate:
    def __init__(self, module):
        """
        :param AnsibleModule module:
        """
        self.args = ""
        self.changed = False
        self.module = module

        self.connection = get_venafi_connection(module)
        self.common_name = module.params[F_CN]
        self.zone = module.params[F_ZONE]
        self.csr_origin = module.params[F_CSR_ORIGIN]
        self.chain_option = module.params[F_CHAIN_OPTION]
        self.before_expired_hours = module.params[F_B4_EXPIRED_HOURS]
        self.use_pkcs12 = module.params[F_USE_PKCS12]
        self.validity_hours = module.params[F_VALIDITY_HOURS]
        hint = module.params[F_ISSUER_HINT]
        self.issuer_hint = get_issuer_hint(hint)
        self.custom_fields = module.params[F_CUSTOM_FIELDS]  # type: dict

        self.certificate_filename = module.params[F_CERT_PATH]
        self.chain_filename = module.params[F_CHAIN_PATH]
        self.csr_path = module.params[F_CSR_PATH]
        self.privatekey_filename = module.params[F_PK_PATH]

        self.privatekey_type = module.params[F_PK_TYPE]
        self.privatekey_curve = module.params[F_PK_CURVE]
        self.privatekey_size = module.params[F_PK_SIZE]
        self.privatekey_passphrase = module.params[F_PK_PASSPHRASE]
        self.privatekey_reuse = module.params[F_PK_REUSE]
        if self.privatekey_curve and not self.privatekey_type:
            module.fail_json(msg="%s should be set if %s configured" % (F_PK_TYPE, F_PK_CURVE))
        if self.privatekey_size and not self.privatekey_type:
            module.fail_json(msg="%s should be set if %s configured" % (F_PK_TYPE, F_PK_SIZE))
        self.serialize_private_key = False

        self.ip_addresses = []
        self.email_addresses = []
        self.san_dns = []
        self.changed_message = []
        if module.params[F_ALT_NAMES]:
            for n in module.params[F_ALT_NAMES]:
                if n.startswith(("IP:", "IP Address:")):
                    ip = n.split(":", 1)[1]
                    self.ip_addresses.append(ip)
                elif n.startswith("DNS:"):
                    ns = n.split(":", 1)[1]
                    self.san_dns.append(ns)
                elif n.startswith("email:"):
                    mail = n.split(":", 1)[1]
                    self.email_addresses.append(mail)
                else:
                    self.module.fail_json(msg="Failed to determine extension type: %s" % n)

        # If csr_path exists, it takes priority over any other value (csr_origin)
        if os.path.exists(self.csr_path) and os.path.isfile(self.csr_path):
            self.csr_origin = CSR_ORIGIN_PROVIDED

    def check_dirs_existed(self):
        cert_dir = os.path.dirname(self.certificate_filename or "/a")
        key_dir = os.path.dirname(self.privatekey_filename or "/a")
        chain_dir = os.path.dirname(self.chain_filename or "/a")
        ok = True
        for p in [cert_dir, key_dir, chain_dir]:
            if os.path.isdir(p):
                continue
            elif os.path.exists(p):
                self.module.fail_json(msg="Path %s already exists but this is not directory" % p)
            elif not os.path.exists(p):
                self.module.fail_json(msg="Directory %s does not exists" % p)
            ok = False
        return ok

    def _check_private_key_correct(self):
        if not self.privatekey_filename:
            return None
        if not os.path.exists(self.privatekey_filename):
            return False
        private_key = to_text(open(self.privatekey_filename, "rb").read())

        r = CertificateRequest(private_key=private_key,
                               key_password=self.privatekey_passphrase)
        key_type = {"RSA": "rsa", "ECDSA": "ec", "EC": "ec"}.get(self.privatekey_type)
        if key_type and key_type != r.key_type.key_type:
            return False
        if key_type == "rsa" and self.privatekey_size:
            if self.privatekey_size != r.key_type.option:
                return False
        if key_type == "ec" and self.privatekey_curve:
            if self.privatekey_curve != r.key_type.option:
                return False
        return True

    def enroll(self):
        request = CertificateRequest(
            common_name=self.common_name,
            key_password=self.privatekey_passphrase,
            origin="Red Hat Ansible",
            csr_origin=self.csr_origin,
            validity_hours=self.validity_hours,
            issuer_hint=self.issuer_hint,
            ip_addresses=self.ip_addresses,
            san_dns=self.san_dns,
            email_addresses=self.email_addresses,
        )
        request.chain_option = self.chain_option
        zone_config = self.connection.read_zone_conf(self.zone)
        request.update_from_zone_config(zone_config)

        if self.csr_origin == CSR_ORIGIN_SERVICE:
            if request.key_password is None:
                self.module.fail_json(msg="Missing parameter for Service Generated CSR: %s" % F_PK_PASSPHRASE)
            request.include_private_key = True
            self.serialize_private_key = True

        elif self.csr_origin == CSR_ORIGIN_PROVIDED:
            if not self.csr_path:
                self.module.fail_json(msg="Missing parameter for User Provided CSR: %s" % F_CSR_PATH)
            try:
                csr = open(self.csr_path, "rb").read()
                request.csr = csr
            except Exception as e:
                self.module.fail_json(msg="Failed to read CSR file: %s.\nIO Error: %s" % (self.csr_path, str(e)))

        elif self.csr_origin == CSR_ORIGIN_LOCAL:
            if self._check_private_key_correct() and not self.privatekey_reuse:
                private_key = to_text(open(self.privatekey_filename, "rb").read())
                request.private_key = private_key
            elif self.privatekey_type:
                key_type = {"RSA": "rsa", "ECDSA": "ec", "EC": "ec"}.get(self.privatekey_type)
                if not key_type:
                    self.module.fail_json(msg=("Failed to determine key type: %s. Must be RSA or ECDSA"
                                               % self.privatekey_type))
                if key_type == "rsa":
                    request.key_type = KeyType(KeyType.RSA, self.privatekey_size)
                elif key_type == "ecdsa" or key_type == "ec":
                    request.key_type = KeyType(KeyType.ECDSA, self.privatekey_curve)
                else:
                    self.module.fail_json(msg=("Failed to determine key type: %s. Must be RSA or ECDSA"
                                               % self.privatekey_type))
                self.serialize_private_key = True
        else:
            self.module.fail_json(msg="Failed to determine %s: %s" % (F_CSR_ORIGIN, self.csr_origin))

        if self.custom_fields:
            cf_list = []
            for key, value in self.custom_fields.items():
                if isinstance(value, list):
                    # Multiple values for same entry
                    for item in value:
                        cf_list.append(CustomField(name=key, value=item))
                else:
                    cf_list.append(CustomField(name=key, value=value))
            request.custom_fields = cf_list

        self.connection.request_cert(request, self.zone)
        cert = self.connection.retrieve_cert(request)

        if self.use_pkcs12:
            self.certificate_filename = self._get_pkcs12_cert_path()
            self._atomic_write(self.certificate_filename, cert.as_pkcs12(passphrase=self.privatekey_passphrase))
        elif self.chain_filename:
            self._atomic_write(self.chain_filename, "\n".join(cert.chain))
            self._atomic_write(self.certificate_filename, cert.cert)
        else:
            self._atomic_write(self.certificate_filename, cert.full_chain)

        if self.serialize_private_key and cert.key is not None:
            self._atomic_write(self.privatekey_filename, cert.key)

    def _get_pkcs12_cert_path(self):
        """

        :rtype: str
        """
        if self.certificate_filename.endswith(".pfx") or self.certificate_filename.endswith(".p12"):
            return self.certificate_filename
        else:
            index = len(self.certificate_filename)
            index -= 4
            pkcs12_name = self.certificate_filename[0:index]
            return "%s.p12" % pkcs12_name

    def _atomic_write(self, path, content):
        suffix = ".atomic_%s" % random.randint(100, 100000)
        try:
            with open(path + suffix, "wb") as f:
                f.write(to_bytes(content))
        except OSError as e:
            self.module.fail_json(msg="Failed to write file %s: %s" % (
                path + suffix, e))

        self.module.atomic_move(path + suffix, path)
        self.changed = True
        self._check_and_update_permissions(path)

    def _check_and_update_permissions(self, path):
        file_args = self.module.load_file_common_arguments(self.module.params)
        file_args['path'] = path
        if self.module.set_fs_attributes_if_different(file_args, False):
            self.changed = True

    @staticmethod
    def _check_dns_sans_correct(actual, required, optional):
        if len(optional) == 0 and len(actual) != len(required):
            return False
        for i in required:
            found = False
            for j in actual:
                if i == j:
                    found = True
                    break
            if not found:
                return False
        combined = required + optional
        for i in actual:
            found = False
            for j in combined:
                if i == j:
                    found = True
                    break
            if not found:
                return False
        return True

    def _check_certificate_validity(self, cert, validate):
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn != self.common_name:
            self.changed_message.append(
                'Certificate CN %s not matched to expected %s'
                % (cn, self.common_name)
            )
            return False
        # Check if certificate not already expired
        if cert.not_valid_after < datetime.datetime.now():
            self.changed_message.append(
                'Certificate expiration date %s '
                'is less than current time %s (certificate expired)'
                % (cert.not_valid_after, self.before_expired_hours)
            )
            return False
        # Check if certificate expiring time is greater than
        # before_expired_hours (only for creating new certificate)
        if not validate:
            if cert.not_valid_after - datetime.timedelta(
                    hours=self.before_expired_hours) < datetime.datetime.now():
                self.changed_message.append(
                    'Hours before certificate expiration date %s '
                    'is less than before_expired_hours value %s'
                    % (cert.not_valid_after, self.before_expired_hours)
                )
                return False
        if cert.not_valid_before - datetime.timedelta(
                hours=24) > datetime.datetime.now():
            self.changed_message.append(
                "Certificate expiration date %s "
                "is set to future from server time %s."
                % (cert.not_valid_before - datetime.timedelta(hours=24),
                   (datetime.datetime.now()))
            )
            return False
        ips = []
        dns = []
        alt_names = []
        if cert.extensions:
            ext = cert.extensions
            try:
                alt_names = ext.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            except x509.extensions.ExtensionNotFound as enf:
                # If the OID is not found, the x509 object raises an error we need to catch.
                alt_names = []

        for e in alt_names:
            if isinstance(e, x509.general_name.DNSName):
                dns.append(e.value)
            elif isinstance(e, x509.general_name.IPAddress):
                ips.append(e.value.exploded)
        if self.ip_addresses and sorted(self.ip_addresses) != sorted(ips):
            self.changed_message.append("IP address in request: %s and in certificate: %s are different"
                                        % (sorted(self.ip_addresses), ips))
            self.changed_message.append("CN is %s" % cn)
            return False
        if self.san_dns and not self._check_dns_sans_correct(
                dns, self.san_dns, [self.common_name]):
            self.changed_message.append("DNS addresses in request: %s and in certificate: %s are different"
                                        % (sorted(self.san_dns), sorted(dns)))
            return False
        return True

    def _check_public_key_matched_to_private_key(self, cert):
        if not self.privatekey_filename:
            return True
        if not os.path.exists(self.privatekey_filename):
            return False if self.serialize_private_key else True
        try:
            with open(self.privatekey_filename, 'rb') as key_data:
                password = self.privatekey_passphrase.encode() if \
                    self.privatekey_passphrase else None
                pkey = serialization.load_pem_private_key(
                    key_data.read(), password=password,
                    backend=default_backend())

        except OSError as exc:
            self.module.fail_json(
                msg="Failed to read private key file: %s" % exc)

        cert_public_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        private_key_public_key_pem = pkey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        if cert_public_key_pem != private_key_public_key_pem:
            return False
        return True

    def _check_files_permissions(self):
        files = (self.privatekey_filename, self.certificate_filename,
                 self.chain_filename)
        return all(self._check_file_permissions(x) for x in files)

    def _check_file_permissions(self, path, update=False):
        return True  # todo: write

    def check(self, validate):
        """Return true if running will change anything"""
        result = {
            'cert_file_exists': True,
            'changed': False,
        }
        if not os.path.exists(self.certificate_filename):
            result = {
                'cert_file_exists': False,
                'changed': True,
                'changed_msg':
                    self.changed_message.append(STRING_CERT_FILE_NOT_EXISTS),
            }
        else:
            try:
                with open(self.certificate_filename, 'rb') as cert_data:
                    try:
                        if self.use_pkcs12:
                            b_pass = self.privatekey_passphrase.encode() if self.privatekey_passphrase else None
                            # pylint: disable=disallowed-name
                            pk, cert, _ = pkcs12.load_key_and_certificates(cert_data.read(), b_pass, default_backend())
                        else:
                            cert = x509.load_pem_x509_certificate(cert_data.read(), default_backend())
                    except Exception:
                        self.module.fail_json(msg="Failed to load certificate from file: %s"
                                                  % self.certificate_filename)
            except OSError as exc:
                self.module.fail_json(msg="Failed to read certificate file: %s" % exc)

            if not self._check_public_key_matched_to_private_key(cert):
                result['changed'] = True
                self.changed_message.append(STRING_PKEY_NOT_MATCHED)

            if not self._check_certificate_validity(cert, validate):
                result['changed'] = True
                self.changed_message.append(
                    STRING_FAILED_TO_CHECK_CERT_VALIDITY)

        if self._check_private_key_correct() is False:  # may be None
            result['changed'] = True
            self.changed_message.append(STRING_BAD_PKEY)

        if not self._check_files_permissions():
            result['changed'] = True
            self.changed_message.append(STRING_BAD_PERMISSIONS)

        result['changed_msg'] = ' | '.join(self.changed_message)
        return result

    def validate(self):
        """Ensure the resource is in its desired state."""
        result = self.check(validate=True)
        if result['changed']:
            self.module.fail_json(
                msg=result['changed_msg']
            )

    def dump(self):

        result = {
            'changed': self.changed,
            'privatekey_filename': self.privatekey_filename,
            'privatekey_size': self.privatekey_size,
            'privatekey_curve': self.privatekey_curve,
            'privatekey_type': self.privatekey_type,
            'certificate_filename': self.certificate_filename,
            'chain_filename': self.chain_filename,
        }

        return result


def main():
    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    args = module_common_argument_spec()
    args.update(venafi_common_argument_spec())
    args.update(
        # General properties of a certificate
        alt_name=dict(type='list', aliases=['subjectAltName'], elements='str'),
        before_expired_hours=dict(type='int', required=False, default=72),
        chain_option=dict(type='str', required=False, default='last'),
        chain_path=dict(type='path', required=False),
        common_name=dict(aliases=['CN', 'commonName', 'common_name'], type='str', required=True),
        csr_origin=dict(type='str', choices=[CSR_ORIGIN_LOCAL, CSR_ORIGIN_SERVICE, CSR_ORIGIN_PROVIDED],
                        default=CSR_ORIGIN_LOCAL),
        csr_path=dict(type='path', required=False),
        custom_fields=dict(type='dict', required=False),
        issuer_hint=dict(type='str', choices=[DEFAULT, DIGICERT, ENTRUST, MICROSOFT], default=DEFAULT, required=False),
        path=dict(type='path', aliases=['cert_path'], required=True),
        privatekey_curve=dict(type='str', required=False),
        privatekey_passphrase=dict(type='str', no_log=True),
        privatekey_path=dict(type='path', required=False),
        privatekey_reuse=dict(type='bool', required=False, default=True),
        privatekey_size=dict(type='int', required=False),
        privatekey_type=dict(type='str', required=False),
        renew=dict(type='bool', required=False, default=True),
        use_pkcs12_format=dict(type='bool', default=False, required=False),
        validity_hours=dict(type='int', required=False),
        zone=dict(type='str', required=False, default='')
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
    vcert = VCertificate(module)
    change_dump = vcert.check(validate=False)
    if module.check_mode:
        module.exit_json(**change_dump)

    if not vcert.check_dirs_existed():
        module.fail_json(msg="Dirs not existed")
    if change_dump['changed']:
        # TODO: Cover it by tests
        """
        make a following choice:
        1. If certificate is present and renew is true validate it
        2. If certificate not present renew it
        3. If it present and renew is false just keep it.
        """
        if change_dump['cert_file_exists']:
            if module.params['renew']:
                vcert.enroll()
            else:
                module.exit_json(**change_dump)
        else:
            vcert.enroll()
    elif module.params['force']:
        vcert.enroll()
    vcert.validate()
    result = vcert.dump()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
