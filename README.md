![Venafi](Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi Collection for Ansible

This collection, called `machine_identity`, uses Venafi Trust Protection Platform (TPP) or Venafi as a Service (VaaS)
to provide certificates and keys to Ansible solutions involving machine identities.

If you like this collection, please give us a rating on [Ansible Galaxy](https://galaxy.ansible.com/venafi/machine_identity).

## Requirements

Review the [Venafi](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
prerequisites, then install Ansible and [VCert-Python](https://github.com/Venafi/vcert-python) (v0.11.2 or higher) using `pip`:
```sh
pip install ansible vcert --upgrade
```

## Collection Contents

### Roles

- [`venafi.machine_identity.certificate`](roles/certificate/README.md): Enrolls a certificate and optionally deploys it to a remote location.
- [`venafi.machine_identity.policy`](roles/policy/README.md): Creates or updates certificate policy on VaaS or TPP using a specification file.

## Version History

#### 0.7.5
 * Added ability to retrieve public key and default principals from SSH Certificate Authorities
#### 0.7.4
 * Fixed issues with doc-string and custom fields description.
 * Added version history to README.md
#### 0.7.3
 * Added support for Service Generated CSR (contribution by @Kerrida)
 * Added support for PKCS12 output format for certificates. 
 * Added support for flexible validity periods when requesting a certificate. 
 * Added support for custom fields when requesting a certificate.
#### 0.7.2
 * Minor fixes to SSH certificates on TPP.
#### 0.7.1
 * Cleaned linter warnings on the collection.
#### 0.7.0
 * Added support for SSH certificates (request, retrieve) on TPP.
#### 0.6.0
 * Migrated from Venafi Ansible role to Machine Identity collection. 
 * Added support for Policy Management on TPP and VaaS

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full license text.

Please direct questions/comments to opensource@venafi.com.
