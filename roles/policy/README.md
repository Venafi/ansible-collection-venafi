[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![CyberArk Certificate Manager, Self-Hosted 17.3+ & CyberArk Certificate Manager, SaaS](https://img.shields.io/badge/Compatibility-Certificate%20Manager%2C%20Self--Hosted_17.3%2B_%26Certificate%20Manager%2C%20SaaS-f9a90c)
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# CyberArk `policy` Role for Ansible

This role enables "Policy as Code" for [CyberArk Certificate Manager, Self-Hosted](https://www.cyberark.com/products/certificate-manager/),
[CyberArk Certificate Manager, SaaS](https://www.cyberark.com/products/certificate-manager/), or Strata Cloud Manager (NGTS) using [Red Hat Ansible](https://www.ansible.com/).  With it, certificate policy
documented by specification files can be applied to CyberArk to ensure compliance with enterprise standards.

## Requirements

Review the [CyberArk](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
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

   **CyberArk Certificate Manager, Self-Hosted**:
   
   ```sh
   cat <<EOF >>credentials.yml
   access_token: 'p0WTt3sDPbzm2BDIkoJROQ=='
   url: 'https://tpp.venafi.example'
   zone: "DevOps\\Ansible"
   trust_bundle: "/path/to/bundle.pem"
   EOF
   ```

   **CyberArk Certificate Manager, SaaS**:
   
   ```sh
   cat <<EOF >>credentials.yml
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **CyberArk Certificate Manager, SaaS EU**:
   
   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.venafi.eu'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```
   
   **CyberArk Certificate Manager, SaaS AU**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.au.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **CyberArk Certificate Manager, SaaS UK**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.uk.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **CyberArk Certificate Manager, SaaS SG**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.sg.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **CyberArk Certificate Manager, SaaS CA**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.ca.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **NGTS (Strata Cloud Manager)** — production (omit `url` and `token_url` to use the Palo Alto production endpoints):

   ```sh
   cat <<EOF >>credentials.yml
   client_id: 'svc-account@1234567890.iam.panserviceaccount.com'
   client_secret: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   tsg_id: '1234567890'
   zone: 'my-issuing-template'
   EOF
   ```

   **NGTS (Strata Cloud Manager)** — non-production (set both `url` and the environment's `token_url`):

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://dev.api.sase.paloaltonetworks.com/ngts'
   token_url: 'https://auth.dev.appsvc.paloaltonetworks.com/auth/v1/oauth2/access_token'
   client_id: 'svc-account@1234567890.iam.panserviceaccount.com'
   client_secret: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   tsg_id: '1234567890'
   zone: 'my-issuing-template'
   EOF
   ```

   > NGTS (Strata Cloud Manager) has no Application or owner layer, so the `users` and `owners` in
   > the policy specification are ignored and read back empty. The `tsg_id` (or the TSG ID inside
   > `scope`) must be a 10-digit integer.

   The policy role supports the following connection and credential settings:
   
   | Variable Name  | Description                                                                                                                                                                                |
   |----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
   | `access_token` | CyberArk Certificate Manager, Self-Hosted access token for the "ansible-by-venafi" API Application                                                                                         |
   | `client_id`    | NGTS (Strata Cloud Manager) OAuth2 service-account client id. Supplying `client_id` and `client_secret` selects the NGTS connection                                                        |
   | `client_secret`| NGTS (Strata Cloud Manager) OAuth2 service-account client secret                                                                                                                          |
   | `password`     | **[DEPRECATED]** CyberArk Certificate Manager, Self-Hosted WebSDK password, use `access_token` if possible                                                                                 |
   | `scope`        | NGTS (Strata Cloud Manager) OAuth2 scope in the form "tsg_id:<TSG_ID>". Provide `scope` or `tsg_id`                                                                                        |
   | `test_mode`    | When "true", the role operates without connecting to CyberArk Certificate Manager, Self-Hosted or CyberArk Certificate Manager, SaaS                                                       |
   | `token`        | CyberArk Certificate Manager, SaaS API key                                                                                                                                                 |
   | `token_url`    | NGTS (Strata Cloud Manager) OAuth2 token endpoint. Optional; defaults to the Palo Alto production endpoint, set it only for non-production environments                                    |
   | `trust_bundle` | Text file containing trust anchor certificates in PEM (text) format, generally required for CyberArk Certificate Manager, Self-Hosted                                                      |
   | `tsg_id`       | NGTS (Strata Cloud Manager) tenant service group id (a 10-digit integer). Provide `tsg_id` or `scope`                                                                                      |
   | `url`          | CyberArk Certificate Manager, Self-Hosted URL (e.g. "https://tpp.venafi.example"). For NGTS, optional; defaults to the Palo Alto production endpoint                                        |
   | `user`         | **[DEPRECATED]** CyberArk Certificate Manager, Self-Hosted WebSDK username, use `access_token` if possible                                                                                 |
   | `zone`         | Policy folder for CyberArk Certificate Manager, Self-Hosted; Application name and Issuing Template API Alias for SaaS (e.g. "Business App\Enterprise CIT"); Issuing Template alias only for NGTS |

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
   
   | Platform                                  | Result                                                                                                                                                                              |
   |-------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
   | CyberArk Certificate Manager, Self-Hosted | a policy folder with the values specified on `sample_policy_spec.json` on the path specified by the `zone` setting                                                                  |
   | CyberArk Certificate Manager, SaaS        | an Application and Certificate Issuing Template with the values specified on `sample_policy_spec.json` with names given by the `zone` setting. (e.g. "Business App\Enterprise CIT") |
   | NGTS (Strata Cloud Manager)               | a Certificate Issuing Template with the values specified on `sample_policy_spec.json` with the alias given by the `zone` setting (e.g. "my-issuing-template"). No Application is created |
   
   The `--ask-vault-pass` parameter is needed if you encrypted the `credentials.yml` file.
   
## License

Copyright &copy; Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](../../LICENSE) for the full license text.

Please direct questions/comments to mis-opensource@cyberark.com.
