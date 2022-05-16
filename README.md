[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi Collection for Ansible

This collection, called `machine_identity`, uses [Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi as a Service](https://www.venafi.com/venaficloud) to provide keys and certificates to Ansible solutions that require machine identity management.

If you like this collection, please give us a rating on [Ansible Galaxy](https://galaxy.ansible.com/venafi/machine_identity).

## Requirements

Review the [Venafi](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
prerequisites, then install Ansible and [VCert-Python](https://github.com/Venafi/vcert-python) (v0.11.2 or higher) using `pip`:
```sh
pip install ansible vcert --upgrade
```
<!-- TODO: clarify the different requirements for TPP and VaaS -->

## Collection Contents

### Roles

- [`venafi.machine_identity.certificate`](roles/certificate/README.md): Enrolls a certificate and optionally deploys it to a remote location.
- [`venafi.machine_identity.policy`](roles/policy/README.md): Creates or updates certificate policy on VaaS or TPP using a specification file.

## Version History

[Check version history here](docs/version_history.md)

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full license text.

Please direct questions/comments to opensource@venafi.com.
