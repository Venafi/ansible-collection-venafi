# Venafi Collection for Ansible

## Version History

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
