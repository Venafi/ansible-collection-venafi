![Venafi](../Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_
# Venafi Collection for Ansible
## Version History

#### 0.8.1
* Fixed issue with SANs validation when no SAN has been provided
* Fixed issue when an empty private key file was being created on invalid scenarios
#### 0.8.0
 * Added support for service generated CSR on VaaS.
#### 0.7.5
 * Added ability to retrieve public key and default principals from SSH Certificate Authorities
#### 0.7.4
 * Fixed issues with doc-string and custom fields description
 * Added version history to README.md
#### 0.7.3
 * Added support for Service Generated CSR (contribution by @Kerrida) on TPP
 * Added support for PKCS12 output format for certificates
 * Added support for flexible validity periods when requesting a certificate
 * Added support for custom fields when requesting a certificate
#### 0.7.2
 * Minor fixes to SSH certificates on TPP
#### 0.7.1
 * Cleaned linter warnings on the collection
#### 0.7.0
 * Added support for SSH certificates (request, retrieve) on TPP
#### 0.6.0
 * Migrated from Venafi Ansible role to Machine Identity collection
 * Added support for Policy Management on TPP and VaaS