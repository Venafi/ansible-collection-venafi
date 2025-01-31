![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi `policy` Role for Ansible

This role enables "Policy as Code" for [Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform)
or [Venafi as a Service](https://vaas.venafi.com/) using [Red Hat Ansible](https://www.ansible.com/).  With it, certificate policy
documented by specification files can be applied to Venafi to ensure compliance with enterprise standards.

## Requirements

Review the [Venafi](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
prerequisites, then install Ansible and [VCert-Python](https://github.com/Venafi/vcert-python) (v0.11.2 or higher) using `pip`:
```sh
pip install ansible vcert --upgrade
```

## Using with Ansible Galaxy

For more information about Ansible Galaxy, go to https://galaxy.ansible.com/docs/using/installing.html    

1. Install the [Machine Identity Collection](https://galaxy.ansible.com/venafi/machine_identity) from Ansible Galaxy:

   ```sh
   ansible-galaxy collection install venafi.machine_identity
   ```

1. Create the `credentials.yml` and populate it with connection parameters:

   **Trust Protection Platform**:
   
   ```sh
   cat <<EOF >>credentials.yml
   access_token: 'p0WTt3sDPbzm2BDIkoJROQ=='
   url: 'https://tpp.venafi.example'
   zone: "DevOps\\Ansible"
   trust_bundle: "/path/to/bundle.pem"
   EOF
   ```

   **Venafi as a Service**:
   
   ```sh
   cat <<EOF >>credentials.yml
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **Venafi as a Service EU**:
   
   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.venafi.eu'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```
   
   **Venafi as a Service AU**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.au.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   The policy role supports the following connection and credential settings:
   
   | Variable Name  | Description                                                  |
   | -------------- | ------------------------------------------------------------ |
   | `access_token` | Trust Protection Platform access token for the "ansible-by-venafi" API Application |
   | `password`     | **[DEPRECATED]** Trust Protection Platform WebSDK password, use `access_token` if possible |
   | `test_mode`    | When "true", the role operates without connecting to Trust Protection Platform or Venafi as a Service |
   | `token`        | Venafi as a Service API key                                         |
   | `trust_bundle` | Text file containing trust anchor certificates in PEM (text) format, generally required for Trust Protection Platform |
   | `url`          | Venafi service URL (e.g. "https://tpp.venafi.example") |
   | `user`         | **[DEPRECATED]** Trust Protection Platform WebSDK username, use `access_token` if possible |
   | `zone`         | Policy folder for TPP or Application name and Issuing Template API Alias for VaaS (e.g. "Business App\Enterprise CIT") |

1. Use `ansible-vault` to encrypt the `credentials.yml` file using a password.  This is optional but highly recommended.
   As long as you know the password you can always decrypt the file to make changes and then re-encrypt it.
   Go to https://docs.ansible.com/ansible/latest/user_guide/vault.html for more information.

   ```sh
   ansible-vault encrypt credentials.yml
   ```

1. Create a policy specification file `sample_policy_spec.json`
   
1. Write a simple playbook called, for example, `policy_sample.yml`.

   ```yaml
   - hosts: localhost
     roles:
       - role: venafi.machine_identity.policy
         policy_spec_path: "/tmp/etc/ssl/sample_policy_spec.json"
   ```

1. Run the playbook.

   ```sh
   ansible-playbook policy_sample.yml --ask-vault-pass
   ```
   
   Running this playbook will create:
   
   | Platform            | Result |
   | ------------------- | ------ |
   | Trust Protection    | a policy folder with the values specified on `sample_policy_spec.json` on the path specified by the `zone` setting |
   | Venafi as a Service | an Application and Certificate Issuing Template with the values specified on `sample_policy_spec.json` with names given by the `zone` setting. (e.g. "Business App\Enterprise CIT") |
   
   The `--ask-vault-pass` parameter is needed if you encrypted the `credentials.yml` file.
   
## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](../../LICENSE) for the full license text.

Please direct questions/comments to opensource@venafi.com.
