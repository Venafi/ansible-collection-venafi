# Venafi Collection for Ansible

## Version History

##### 1.2.0
* Bumped the `vcert` dependency to `vcert>=0.20.0` in `requirements.in` and regenerated the hash-pinned `requirements.txt` lockfile (`vcert==0.20.0`). `vcert` 0.20.0 adds NGTS policy management on top of the NGTS support and security fixes introduced in 0.19.0 — sensitive data redacted from debug logs (CWE-532), safe YAML loading in the policy parser (CWE-502), and TLS verification enabled by default with a warning when disabled (CWE-295). These are backward compatible: the collection already passes `verify` only when a `trust_bundle` is supplied (otherwise `requests`' default of verified TLS applies) and uses plain-data policy specs.
* Added support for NGTS (Strata Cloud Manager) certificate enrollment and renewal in the `venafi_certificate` module and `certificate` role. NGTS is selected by supplying the OAuth2 service-account credentials (`client_id`, `client_secret`, and `tsg_id` or `scope`); `url` and `token_url` are optional and default to the Palo Alto production endpoints.
* Added support for NGTS (Strata Cloud Manager) policy management (`get_policy`/`set_policy`) in the `venafi_policy` module and `policy` role. NGTS zones are the issuing-template (CIT) alias only — there is no Application or owner layer, so the policy specification's `users` and `owners` are ignored and read back empty (parity with the Go reference implementation).
* NGTS supports certificate and policy operations. The `venafi_ssh_certificate` and `venafi_ssh_ca` modules fail fast with a clear message when NGTS credentials are supplied.

##### 1.1.2
* Required changes to upload the version 1.1.2 in RedHat Ansible Automation Platform for rebranding.
* Also includes fix for issue that would trigger when "csr_path" is not defined in playbook.
##### 1.1.1
* Required changes to upload the version 1.1.0 in RedHat Ansible Automation Platform. There is not any change in the functionality.
##### 1.1.0
* Added support for CyberArk Certificate Manager, Self-Hosted 25.1 and above
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
 * Added support for service generated CSR on CyberArk Certificate Manager, SaaS
 * Fixed issue with SANs validation when no SAN has been provided
 * Fixed issue when an empty private key file was being created on invalid scenarios
#### 0.7.5
 * Added ability to retrieve public key and default principals from SSH Certificate Authorities
#### 0.7.4
 * Fixed issues with doc-string and custom fields description
 * Added version history to README.md
#### 0.7.3
 * Added support for Service Generated CSR (contribution by @Kerrida) on CyberArk Certificate Manager, Self-Hosted
 * Added support for PKCS12 output format for certificates
 * Added support for flexible validity periods when requesting a certificate
 * Added support for custom fields when requesting a certificate
#### 0.7.2
 * Minor fixes to SSH certificates on CyberArk Certificate Manager, Self-Hosted
#### 0.7.1
 * Cleaned linter warnings on the collection
#### 0.7.0
 * Added support for SSH certificates (request, retrieve) on CyberArk Certificate Manager, Self-Hosted
#### 0.6.0
 * Migrated from CyberArk Ansible role to Machine Identity collection
 * Added support for Policy Management on CyberArk Certificate Manager, Self-Hosted and CyberArk Certificate Manager, SaaS
