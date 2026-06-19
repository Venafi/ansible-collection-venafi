[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![CyberArk Certificate Manager, Self-Hosted 17.3+ & CyberArk Certificate Manager, SaaS](https://img.shields.io/badge/Compatibility-Certificate%20Manager%2C%20Self--Hosted_17.3%2B_%26Certificate%20Manager%2C%20SaaS-f9a90c)  
_To report a problem or share an idea, use **[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too. In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi Collection for Ansible

This collection, called `machine_identity`, uses [CyberArk Certificate Manager, Self-Hosted](https://www.cyberark.com/products/certificate-manager/) or [CyberArk Certificate Manager, SaaS](https://www.cyberark.com/products/certificate-manager/) to provide keys and certificates to Ansible solutions that require machine identity management.

If you like this collection, please give us a rating on [Ansible Galaxy](https://galaxy.ansible.com/venafi/machine_identity).
## Requirements

Review the [CyberArk](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
prerequisites, and depending on the source:

### Ansible Automation Platform

- Install [VCert-Python](https://github.com/Venafi/vcert-python) (v0.18.0 or higher) using `pip`:

```sh
pip install vcert --upgrade
```

### Ansible Galaxy

- Install both Ansible and [VCert-Python](https://github.com/Venafi/vcert-python) (v0.18.0 or higher) using `pip`:

```sh
pip install ansible vcert --upgrade
```

<!-- TODO: clarify the different requirements for CyberArk Certificate Manager, Self-Hosted and CyberArk Certificate Manager, SaaS -->

## Python version compatibility
This collection depends on vcert-python. Due to this, collection requires Python 3.6 or greater.

CyberArk has also announced the end of support for Python less than 3.6. As such support for Python less than 3.6 by this collection has been deprecated.

## Ansible version compatibility
This collection has been tested against the following Ansible versions: >= 2.13

## Installing this collection
You can install the venafi.machine_identity collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install venafi.machine_identity

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: venafi.machine_identity
```

A specific version of the collection can be installed by using the `version` keyword in the `requirements.yml` file:

```yaml
---
collections:
  - name: venafi.machine_identity
    version: 0.10.0
```

The python module dependencies are not installed by `ansible-galaxy`.  They can
be manually installed using pip:

    pip install --require-hashes -r requirements.txt

`requirements.txt` is a generated lockfile. Do not edit it directly. To change
or upgrade a dependency, edit `requirements.in` and run `make lock` (requires
Docker) to regenerate it.

or:

    pip install vcert ansible cryptography

## Collection Contents

### Roles

- [`venafi.machine_identity.certificate`](roles/certificate/README.md): Enrolls a certificate from CyberArk Certificate Manager Self-Hosted, SaaS, or NGTS (Strata Cloud Manager) and optionally deploys it to a remote location.
- [`venafi.machine_identity.policy`](roles/policy/README.md): Creates or updates certificate policy on CyberArk Certificate Manager, SaaS or CyberArk Certificate Manager, Self-Hosted using a specification file.
- [`venafi.machine_identity.ssh_certificate`](roles/ssh_certificate/README.md): Enrolls an SSH certificate using CyberArk Certificate Manager, Self-Hosted.
- [`venafi.machine_identity.ssh_ca`](roles/ssh_ca/README.md): Retrieves public keys of SSH certificate authorities hosted by CyberArk Certificate Manager, Self-Hosted.

## Security Considerations

### Remote Execution Mode

**WARNING**: The `certificate_remote_execution`, `ssh_remote_execution`, and `ssh_ca_remote_execution` options are disabled by default for security reasons. When enabled, these options cause Ansible to transmit your Venafi platform credentials (url, user, password, access_token, token, and the NGTS service-account credentials client_id, client_secret, token_url, tsg_id) to every managed host in your inventory. These credentials are **not** scoped to individual hosts—they can request certificates for any name allowed by the Venafi zone.

**Risk**: If any managed host is compromised, an attacker can extract these zone-wide credentials from temporary files and use them to request trusted certificates for all servers in your infrastructure.

**Recommendations**:
- Only enable remote execution in highly trusted environments where all managed hosts are secured to the same level as your Ansible controller.
- Consider using the default local execution mode (`*_remote_execution: false`), which keeps credentials on the Ansible controller and only copies certificate artifacts to managed hosts.
- If remote execution is required, implement additional controls such as per-host credentials with narrowly-scoped policies.

## Version History

[Check version history here](https://github.com/Venafi/ansible-collection-venafi/blob/main/docs/version_history.md)

## Support

Only the latest release of this collection is supported.

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using 
the Create issue button in the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained 
either from Galaxy or GitHub, you can raise a GitHub Issue directly with the developers [here](https://github.com/Venafi/ansible-collection-venafi/issues)
or get community help available on the [Ansible Forum](https://forum.ansible.com/).

## License

Copyright &copy; Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full license text.

Please direct questions/comments to mis-opensource@cyberark.com
