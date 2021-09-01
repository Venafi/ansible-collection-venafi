![Venafi](../../Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi `ssh_certificate` Role for Ansible

This role adds certificate enrollment capabilities to [Red Hat Ansible](https://www.ansible.com/) by seamlessly
integrating with the [Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform)
in a manner that ensures compliance with corporate security policy and provides visibility into certificate 
issuance enterprise wide.

## Requirements

Review the [Venafi](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
prerequisites, then install Ansible and [VCert-Python](https://github.com/Venafi/vcert-python) (v0.12.1 or higher) using `pip`:
```sh
pip install ansible vcert --upgrade
```

## Using with Ansible Galaxy

For more information about Ansible Galaxy, go to https://galaxy.ansible.com/docs/using/installing.html    

1. Install the [Machine Indentity Collection](https://galaxy.ansible.com/venafi/ansible_role_venafi) from Ansible Galaxy:

   ```sh
   ansible-galaxy collection install venafi.machine_identity
   ```

2. Create the `credentials.yml` and populate it with connection parameters:

   **Trust Protection Platform**:
   
   ```sh
   cat <<EOF >>credentials.yml
   access_token: 'p0WTt3sDPbzm2BDIkoJROQ=='
   url: 'https://tpp.venafi.example.com'
   trust_bundle: "/path/to/bundle.pem"
   EOF
   ```

   **Venafi as a Service**:
    
    >**NOTE:** as of now, VaaS does not support SSH certificates.
   
   The certificate role supports the following connection and credential settings:
   
   | Variable Name  | Description                                                  |
   | -------------- | ------------------------------------------------------------ |
   | `test_mode`    | When "true", the role operates without connecting to Trust Protection Platform or Venafi as a Service |
   | `access_token` | Trust Protection Platform access token for the "ansible-by-venafi" API Application |
   | `user`         | **[DEPRECATED]** Trust Protection Platform WebSDK username, use `access_token` if possible |
   | `password`     | **[DEPRECATED]** Trust Protection Platform WebSDK password, use `access_token` if possible |
   | `trust_bundle` | Text file containing trust anchor certificates in PEM (text) format, generally required for Trust Protection Platform |
   | `url`          | Venafi service URL (e.g. "https://tpp.venafi.example"), generally only applicable to Trust Protection Platform |

3. Use `ansible-vault` to encrypt the `credentials.yml` file using a password.  This is optional but highly recommended.
   As long as you know the password you can always decrypt the file to make changes and then re-encrypt it.
   Go to https://docs.ansible.com/ansible/latest/user_guide/vault.html for more information.

   ```sh
   ansible-vault encrypt credentials.yml
   ```

4. Write a simple playbook called, for example, `ssh_sample.yml`.

   ```yaml
   - name: Sample SSH Certificate playbook
     hosts: localhost
     roles: 
       - role: venafi.machine_identity.ssh_certificate
         ssh_key_id: "my-ssh-key-id"
         ssh_template: "\\VED\\Certificate Authority\\SSH\\Templates\\my-ssh-cit"
         ssh_cert_dir: "/tmp/etc/ssh/"
      ```

5. Run the playbook.

   ```sh
   ansible-playbook ssh_sample.yml --ask-vault-pass
   ```
   
   Running the playbook will generate an SSH certificate and place it into folder in /tmp/etc/ssh/ directory.
   
   By default, the public and private key used for the SSH certificate will also be placed in the same folder as the certificate.
   
   The `--ask-vault-pass` parameter is needed if you encrypted the `credentials.yml` file.
   
 Additional playbook variables can be added to specify properties of the SSH certificate and key pair, file locations, 
   and to override default behaviors.
   
   ```sh
   cat variables.yml
   ```
   The following is the list of variables accepted by the `ssh_certificate` role: 

   | Variable Name                    | Description                                                  |
   | -------------------------------- | ------------------------------------------------------------ |
   | `credentials_file`               | Name of the file containing Venafi credentials and connection settings.<br/>Default: `credentials.yml` |
   | `ssh_remote_execution`           | Specifies whether cryptographic assets will be generated remotely, or locally and then provisioned to the remote host.<br/>Default: `false` |
   | `ssh_key_id`                     | The identifier of the requested certificate.<br/>Default: `"{{ ansible_fqdn }}"`<br/>**Required** |
   | `ssh_cert_dir`                   | Local parent directory where the cryptographic assets will be stored.<br/>Default: `"/etc/ssh/{{ ssh_key_id }}"` |
   | `ssh_cert_path`                  | Local directory where certificate files will be stored.<br/>Default: `"{{ ssh_cert_dir }}/{{ ssh_key_id }}-cert.pub"` |
   | `ssh_public_key_path`            | Local directory where the public key file will be stored.<br/>When `ssh_key_generation_type` is `provided` this option indicates the path to the public key to load.<br/>Default: `"{{ ssh_cert_dir }}/{{ ssh_key_id }}.pub"` |
   | `ssh_private_key_path`           | Local directory where the private key file will be stored.<br/>Ignored when `ssh_key_generation_type` is `provided`.<br/>Default: `"{{ ssh_cert_dir }}/{{ ssh_key_id }}"` |
   | `ssh_remote_cert_path`           | Directory on remote host where SSH certificate file will be stored<br/>Default: `"{{ ssh_cert_dir }}/{{ ssh_key_id }}-cert.pub"` |   
   | `ssh_remote_public_key_path`     | Directory on remote host where public key file will be stored<br/>Default: `"{{ ssh_cert_dir }}/{{ ssh_key_id }}.pub"` |
   | `ssh_remote_private_key_path`    | Directory on remote host where private key file will be stored<br/>Default: `"{{ ssh_cert_dir }}/{{ ssh_key_id }}"` |
   | `ssh_copy_public_key_to_remote`  | If `true`, copies the generated public key to the remote host.<br/>Default: `true`  | 
   | `ssh_copy_private_key_to_remote` | If `true`, copies the generated private key to the remote host.<br/>Default: `true` |
   | `ssh_template`                   | The Domain Name of the issuing certificate template which will be used for signing.<br/>**Required** |
   | `ssh_key_generation_type`        | The generation type of the SSH Key Pair.<br/>`provided`. The user provides a file path `public_key_path` to load the public key data.<br/>`local`. The SSH Key Pair is generated by the vcert library.<br/>`service`. The SSH Key Pair is generated by the TPP server.<br/>Default: `local` |
   | `ssh_private_key_passphrase`     | The passphrase to encrypt the private key.<br/>Ignored when `ssh_key_generation_type` is `provided`. |
   | `ssh_key_size`                   | Size (in bits) of the SSH key to generate.<br/>Default: `3072` |
   | `ssh_validity_period`            | How much time the requester wants to have the certificate valid.<br/>The minimum is 1 second and the maximum is (at least) 20 years.<br/>Default: `specified by the Certificae Authority` |
   | `ssh_policy_dn`                  | The Domain Name of the policy folder where the certificate object will be created.<br/>If this is not specified, then the policy folder specified on the certificate template will be used. |
   | `ssh_object_name`                | The friendly name for the certificate object.<br/>If not specified, then `ssh_key_id` is used. |
   | `ssh_destination_addresses`      | The address (FQDN/hostname/IP/CIDR) of the destination host where the certificate will be used to authenticate to. |
   | `ssh_principals`                 | The requested principals.<br/>If no value is specified, then the default principals from the certificate template will be used. |
   | `ssh_extensions`                 | The requested certificate extensions. Example: `"Extensions" : {"permit-pty": "", "permit-port-forwarding": "", "login@github.com": "alice@github.com"}` |
   | `ssh_force_command`              | The requested force command.<br/>Example: `"ForceCommand": "/usr/scripts/db_backup.sh"` |
   | `ssh_source_addresses`           | The requested source addresses as list of IP/CIDR.<br/>Example: `["192.168.1.1/24", "10.0.0.1"]` |
   | `ssh_windows_cert`               | Indicates that the certificate is intended to be used in a Windows environment.<br/>Break Lines and Carriage Returns will be adjusted accordingly to work on Windows.<br/>Default: `false` |
   | `ssh_force`                      | Execute the task regardless of changes.<br/>Default: `false` |

   Defaults are defined in the [defaults/main.yml](defaults/main.yml) file.
   
## Sample Playbook

```yaml
- hosts: servers
  roles:
    - role: "venafi.machine_identity.ssh_certificate"
      # Required values for SSH certificate
      ssh_template: "\\VED\\Certificate Authority\\SSH\\Templates\\open-source-test-cit"
      ssh_key_id: "{{ ansible_fqdn }}.venafi.example.com"
      # Local files
      ssh_cert_dir: "/tmp/ansible/etc/ssh/{{ ssh_key_id }}"
      ssh_cert_path: "{{ ssh_cert_dir }}/{{ ssh_key_id }}-cert.pub"
      ssh_public_key_path: "{{ ssh_cert_dir }}/{{ ssh_key_id }}.pub"
      ssh_private_key_path: "{{ ssh_cert_dir }}/{{ ssh_key_id }}"
      # Where to execute venafi_ssh_certificate module. If set to false, certificate will be
      # created on ansible master host and then copied to the remote server.
      ssh_remote_execution: false
      # Remote location where to place the certificate.
      ssh_remote_cert_dir: "/etc/ssh"
      ssh_remote_cert_path: "{{ ssh_remote_cert_dir }}/{{ ssh_key_id }}-cert.pub"
      ssh_remote_public_key_path: "{{ ssh_remote_cert_dir }}/{{ ssh_key_id }}.pub"
      ssh_remote_private_key_path: "{{ ssh_remote_cert_dir }}/{{ ssh_key_id }}"
      # Set to false if you don't want to copy public/private key to remote location.
      ssh_copy_private_key_to_remote: true
      ssh_copy_public_key_to_remote: true
```

For more information about using roles go to https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](../../LICENSE) for the full license text.

Please direct questions/comments to opensource@venafi.com.