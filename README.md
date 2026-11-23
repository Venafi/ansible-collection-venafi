[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![CyberArk Certificate Manager, Self-Hosted 17.3+ & CyberArk Certificate Manager, SaaS](https://img.shields.io/badge/Compatibility-Certificate%20Manager%2C%20Self--Hosted_17.3%2B_%26Certificate%20Manager%2C%20SaaS-f9a90c)  
_To report a problem or share an idea, use **[Issues](https://github.com/Venafi/ansible-collection-venafi/issues)**; and if you have a suggestion for fixing the issue, please include those details, too. In addition, use **[Pull Requests](https://github.com/Venafi/ansible-collection-venafi/pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi Collection for Ansible

This collection, called `machine_identity`, uses [CyberArk Certificate Manager, Self-Hosted](https://www.cyberark.com/products/certificate-manager/) or [CyberArk Certificate Manager, SaaS](https://www.cyberark.com/products/certificate-manager/) to provide keys and certificates to Ansible solutions that require machine identity management.

If you like this collection, please give us a rating on [Ansible Galaxy](https://galaxy.ansible.com/venafi/machine_identity).
## Requirements

- **ansible-core 2.16 or later.** The minimum is declared in `meta/runtime.yml`.
- **Python 3.10 or later** on the hosts that run the modules (the Ansible controller, or the
  managed hosts when remote execution is enabled). Python 3.9 is end of life, and current
  releases of the modules' dependencies, such as `requests` and `urllib3`, require Python 3.10.
- **Python packages:** [VCert-Python](https://github.com/Venafi/vcert-python), `cryptography` and
  `certifi`, at the minimum versions listed in the collection's
  [requirements.txt](https://github.com/Venafi/ansible-collection-venafi/blob/main/requirements.txt).
- Review the [VCert-Python prerequisites](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
  for your CyberArk Certificate Manager platform.

### Ansible Automation Platform

When you build an execution environment that includes this collection, `ansible-builder` installs the
Python packages from the collection's `requirements.txt` for you.

### Ansible Galaxy

Install Ansible by following the
[Ansible installation guide](https://docs.ansible.com/ansible/latest/installation_guide/index.html).
`ansible-galaxy` does not install Python packages, so after installing the collection, install them
from the collection's `requirements.txt` (shown here for the default collections path):

```sh
pip install -r ~/.ansible/collections/ansible_collections/venafi/machine_identity/requirements.txt
```

For a reproducible install with exact versions and hashes, use
[test-requirements.txt](https://github.com/Venafi/ansible-collection-venafi/blob/main/test-requirements.txt)
from the GitHub repository:

```sh
pip install --require-hashes -r test-requirements.txt
```

## Installation

Red Hat customers install this certified collection from
[Red Hat Ansible Automation Hub](https://console.redhat.com/ansible/automation-hub). Configure
`ansible-galaxy` to use Automation Hub as described in
[Configuring Ansible Automation Hub](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/latest/html/getting_started_with_automation_hub/index).
The collection is also published on [Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/venafi/machine_identity/).

### Installing the collection

Install this collection with the Ansible Galaxy command-line tool:

```sh
ansible-galaxy collection install venafi.machine_identity
```

### Installing from a requirements file

You can include this collection in a `requirements.yml` file and install it with
`ansible-galaxy collection install -r requirements.yml`:

```yaml
---
collections:
  - name: venafi.machine_identity
```

### Installing a specific version

Use the following syntax to install version 1.5.0:

```sh
ansible-galaxy collection install venafi.machine_identity:==1.5.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/latest/collections_guide/index.html)
for more details.

### Upgrading the collection

To upgrade the collection to the latest available version, run:

```sh
ansible-galaxy collection install venafi.machine_identity --upgrade
```

## Collection Contents

### Roles

- [`venafi.machine_identity.certificate`](https://github.com/Venafi/ansible-collection-venafi/blob/main/roles/certificate/README.md): Enrolls a certificate from CyberArk Certificate Manager Self-Hosted, SaaS, or NGTS (Strata Cloud Manager) and optionally deploys it to a remote location.
- [`venafi.machine_identity.policy`](https://github.com/Venafi/ansible-collection-venafi/blob/main/roles/policy/README.md): Creates or updates certificate policy on CyberArk Certificate Manager, SaaS or CyberArk Certificate Manager, Self-Hosted using a specification file.
- [`venafi.machine_identity.ssh_certificate`](https://github.com/Venafi/ansible-collection-venafi/blob/main/roles/ssh_certificate/README.md): Enrolls an SSH certificate using CyberArk Certificate Manager, Self-Hosted.
- [`venafi.machine_identity.ssh_ca`](https://github.com/Venafi/ansible-collection-venafi/blob/main/roles/ssh_ca/README.md): Retrieves public keys of SSH certificate authorities hosted by CyberArk Certificate Manager, Self-Hosted.

## Security Considerations

### Remote Execution Mode

**WARNING**: The `certificate_remote_execution`, `ssh_remote_execution`, and `ssh_ca_remote_execution` options are disabled by default for security reasons. When enabled, these options cause Ansible to transmit your Venafi platform credentials (url, user, password, access_token, token, and the NGTS service-account credentials client_id, client_secret, token_url, tsg_id) to every managed host in your inventory. These credentials are **not** scoped to individual hosts—they can request certificates for any name allowed by the Venafi zone.

**Risk**: If any managed host is compromised, an attacker can extract these zone-wide credentials from temporary files and use them to request trusted certificates for all servers in your infrastructure.

**Recommendations**:
- Only enable remote execution in highly trusted environments where all managed hosts are secured to the same level as your Ansible controller.
- Consider using the default local execution mode (`*_remote_execution: false`), which keeps credentials on the Ansible controller and only copies certificate artifacts to managed hosts.
- If remote execution is required, implement additional controls such as per-host credentials with narrowly-scoped policies.

## Changelog

The changes in each release are listed in
[CHANGELOG.md](https://github.com/Venafi/ansible-collection-venafi/blob/main/CHANGELOG.md), which is
also included in the collection. See the
[Red Hat Ansible Automation Platform life cycle](https://access.redhat.com/support/policy/updates/ansible-automation-platform)
for the ansible-core versions Automation Platform supports.

## Support

Only the latest release of this collection is supported.

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using 
the Create issue button in the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained 
either from Galaxy or GitHub, you can raise a GitHub Issue directly with the developers [here](https://github.com/Venafi/ansible-collection-venafi/issues)
or get community help available on the [Ansible Forum](https://forum.ansible.com/).

## License

Copyright &copy; Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](https://github.com/Venafi/ansible-collection-venafi/blob/main/LICENSE) for the full license text.

Please direct questions/comments to mis-opensource@cyberark.com
