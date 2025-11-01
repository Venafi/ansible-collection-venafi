[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![CyberArk Certificate Manager, Self-Hosted 17.3+ & CyberArk Certificate Manager, SaaS](https://img.shields.io/badge/Compatibility-Certificate%20Manager%2C%20Self--Hosted_17.3%2B_%26Certificate%20Manager%2C%20SaaS-f9a90c)
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# CyberArk `ssh_ca` Role for Ansible

This role adds SSH Certificate Authority public key retrieval capabilities to [Red Hat Ansible](https://www.ansible.com/) 
by seamlessly integrating with the [CyberArk Certificate Manager, Self-Hosted](https://www.cyberark.com/products/certificate-manager/)
in a manner that ensures compliance with corporate security policy and provides visibility into certificate 
issuance enterprise wide.

## Requirements

Review the [CyberArk](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
prerequisites, then install Ansible and [VCert-Python](https://github.com/Venafi/vcert-python) (v0.12.5 or higher) using `pip`:
```sh
pip install ansible vcert --upgrade
```

## Using with Ansible Galaxy

For more information about Ansible Galaxy, go to https://galaxy.ansible.com/docs/using/installing.html    

1. Install the [Machine Identity Collection](https://galaxy.ansible.com/venafi/machine_identity) from Ansible Galaxy:

   ```sh
   ansible-galaxy collection install venafi.machine_identity
   ```

2. Create the `credentials.yml` and populate it with connection parameters:

   **CyberArk Certificate Manager, Self-Hosted**:
   
   ```sh
   cat <<EOF >>credentials.yml
   access_token: 'p0WTt3sDPbzm2BDIkoJROQ=='
   url: 'https://tpp.venafi.example.com'
   trust_bundle: "/path/to/bundle.pem"
   EOF
   ```

   **CyberArk Certificate Manager, SaaS**:
    
    >**NOTE:** as of now, CyberArk Certificate Manager, SaaS does not support SSH certificates.
   
   The certificate role supports the following connection and credential settings:
   
   | Variable Name  | Description                                                                                                                                               |
   |----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
   | `test_mode`    | When "true", the role operates without connecting to CyberArk Certificate Manager, Self-Hosted or CyberArk Certificate Manager, SaaS                      |
   | `access_token` | CyberArk Certificate Manager, Self-Hosted access token for the "ansible-by-venafi" API Application                                                        |
   | `user`         | **[DEPRECATED]** CyberArk Certificate Manager, Self-Hosted WebSDK username, use `access_token` if possible                                                |
   | `password`     | **[DEPRECATED]** CyberArk Certificate Manager, Self-Hosted WebSDK password, use `access_token` if possible                                                |
   | `trust_bundle` | Text file containing trust anchor certificates in PEM (text) format, generally required for CyberArk Certificate Manager, Self-Hosted                     |
   | `url`          | CyberArk Certificate Manager, Self-Hosted URL (e.g. "https://tpp.venafi.example"), generally only applicable to CyberArk Certificate Manager, Self-Hosted |

3. Use `ansible-vault` to encrypt the `credentials.yml` file using a password.  This is optional but highly recommended.
   As long as you know the password you can always decrypt the file to make changes and then re-encrypt it.
   Go to https://docs.ansible.com/ansible/latest/user_guide/vault.html for more information.

   ```sh
   ansible-vault encrypt credentials.yml
   ```

4. Write a simple playbook called, for example, `ssh_ca_sample.yml`.

   ```yaml
   - name: Sample SSH CA public key playbook
     hosts: localhost
     roles: 
       - role: venafi.machine_identity.ssh_ca
         ssh_ca_public_key_path: "/tmp/etc/ssh/ca/ca-pubkey-file.pub"
         ssh_ca_template: "\\VED\\Certificate Authority\\SSH\\Templates\\my-ssh-cit"
      ```

5. Run the playbook.

   ```sh
   ansible-playbook ssh_ca_sample.yml --ask-vault-pass
   ```
   
   Running the playbook will generate an SSH CA public key and place it into folder in /tmp/etc/ssh/ca directory.
    
   The `--ask-vault-pass` parameter is needed if you encrypted the `credentials.yml` file.
   
 Additional playbook variables can be added to specify properties of the and to override default behaviors.
   
   ```sh
   cat variables.yml
   ```
   The following is the list of variables accepted by the `ssh_ca` role: 

   | Variable Name                   | Description                                                                                                                                                                               |
   | ------------------------------- |-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
   | `credentials_file`              | Name of the file containing CyberArk credentials and connection settings.<br/>Default: `credentials.yml`                                                                                  |
   | `ssh_ca_dir`                    | Local parent directory where the cryptographic assets will be stored.<br/>Default: `"/etc/ssh/{{ ssh_ca_public_key_id }}"`                                                                |
   | `ssh_ca_force`                  | Execute the task regardless of changes.<br/>Default: `false`                                                                                                                              | 
   | `ssh_ca_public_key_filename`    | The name of the file where the CA public key will be stored, with no file extension.<br/>Default: `"{{ ansible_fqdn }}"`                                                                  |
   | `ssh_ca_public_key_path`        | Local directory where the CA public key file will be stored.<br/>Default: `"{{ ssh_ca_dir }}/{{ ssh_ca_public_key_id }}.pub"`                                                             |
   | `ssh_ca_remote_execution`       | Specifies whether cryptographic assets will be generated remotely, or locally and then provisioned to the remote host.<br/>Default: `false`                                               |
   | `ssh_ca_remote_public_key_path` | Directory on remote host where CA public key file will be stored<br/>Default: `"{{ ssh_ca_dir }}/{{ ssh_ca_public_key_id }}.pub"`                                                         |
   | `ssh_ca_template`               | The Domain Name of the SSH Certificate Authority whom the public key is being retrieved.<br/>**Required** if `ssh_ca_guid` not provided                                                   |
   | `ssh_ca_guid`                   | The GUID of the SSH Certificate Authority whom the public key is being retrieved.<br/>**Required** if `ssh_ca_template` not provided                                                      |
   | `ssh_ca_windows_cert`           | Indicates that the public key is intended to be used in a Windows environment.<br/>Break Lines and Carriage Returns will be adjusted accordingly to work on Windows.<br/>Default: `false` |

   Defaults are defined in the [defaults/main.yml](defaults/main.yml) file.
   
## Sample Playbook

```yaml
- hosts: servers
  roles:
    - role: "venafi.machine_identity.ssh_ca"
      # Required values for SSH Certificate Authority public key retrieval
      ssh_ca_template: "\\VED\\Certificate Authority\\SSH\\Templates\\my-test-cit"
      # Local files
      ssh_ca_dir: "/ansible/ssh/ca"
      ssh_ca_public_key_path: "{{ ssh_ca_dir }}/public_key_filename.pub"
      # Where to execute venafi_ssh_ca module. If set to false, CA public key will be
      # created on ansible master host and then copied to the remote server.
      ssh_ca_remote_execution: false
      # Remote location where to place the CA public key.
      ssh_remote_ca_dir: "/etc/ssh"
      ssh_remote_public_key_path: "{{ ssh_remote_ca_dir }}/remote_public_key_filename.pub"
```

For more information about using roles go to https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html

## License

Copyright &copy; Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](../../LICENSE) for the full license text.

Please direct questions/comments to mis-opensource@cyberark.com.
