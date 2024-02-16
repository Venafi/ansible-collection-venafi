# Venafi Collection for Ansible

## Version History

##### 1.0.3
* Updates vcert dependency to v0.17.0 to fix a mismatch between requirements.txt and setup.py dependencies that impacted the collection
#### 1.0.2
* Fixes an issue with csr origin service and private key types
* Updates vcert dependency to v0.16.2
#### 1.0.1
* Added minimum required version of Ansible to the README Requirements section.
* Added minimum required version of Python to the README Requirements section.
* Added collection installation instructions to the README file.
* Fixed changelog file location
* Resolved a couple yamllint test warnings
### 1.0.0
* Release version of venafi.machine_identity collection
#### 0.10.0
 * Fixed linter issues and code changes as prep work for getting the collection certified by Red Hat
#### 0.9.0
 * Updated vcert dependencies to patch security vulnerabilities
 * Fixed all linter errors reported by ansible-lint
 * Added role-specific targets to Makefile
#### 0.8.1
 * Fixed an issue in `local-certificate.yaml` task where certain expressions failed when `use_pkcs12_format` var is not defined
#### 0.8.0
 * Added support for service generated CSR on VaaS
 * Fixed issue with SANs validation when no SAN has been provided
 * Fixed issue when an empty private key file was being created on invalid scenarios
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
