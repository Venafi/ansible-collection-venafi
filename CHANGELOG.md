# Venafi Collection for Ansible

## Version History

##### 1.4.0
* Bumped the `vcert` dependency to `vcert>=0.22.1` in `requirements.in` and regenerated the hash-pinned `requirements.txt` lockfile (`vcert==0.22.1`). `vcert` 0.22.1 delivers, with no collection code change: NGTS (Strata Cloud Manager) service-generated CSR (`csr_origin: service`) enrollment on CIT-only zones — previously failed with `Invalid Zone [...]. The zone format is incorrect` [VC-59232]; working `test_mode: true` enrollment (a duplicate `read_zone_conf` in the fake connector previously raised `NotImplementedError`); tolerance of issuing templates that advertise unrepresentable key sizes/curves during `read_zone`; correct EC-curve casing so service-generated CSRs against curve-constrained templates no longer fail policy validation; and real Ed25519 key generation (an existing Ed25519 key no longer crashes key-type detection).
* Fixed VC-59232 default local-CSR enrollment in `venafi_certificate`: a local CSR with no explicit `privatekey_type` now writes the generated private key to disk. Previously the key file was left unwritten, so the run failed validation with `Private key file does not contain a valid private key`. Also stopped duplicating the failure text when the module's `check()` and `validate()` both ran.
* Fixed `venafi_certificate` ECDSA idempotency: an already-correct ECDSA certificate was re-enrolled on every run because the requested curve (e.g. `P256`) was compared case-sensitively against the SDK's normalized value (`p256`). Curve comparison is now case- and format-insensitive.
* Hardened `venafi_certificate` key parameters: `privatekey_type`, `privatekey_curve`, and `privatekey_size` now declare `choices`, so an invalid value fails with a clear message instead of a raw Python traceback; `privatekey_type: ECDSA` without a curve, or `RSA` without a size, now fall back to the documented defaults (`P521` / `2048`) instead of crashing.
* Added Ed25519 support to `venafi_certificate`: set `privatekey_type: ECDSA` and `privatekey_curve: ed25519` (requires `vcert>=0.22.0`).
* Fixed the `policy` role silently dropping NGTS credentials: the role now forwards `client_id`, `client_secret`, `token_url`, `tsg_id`, and `scope` to `venafi_policy`, so NGTS policy management works through the role (previously it failed with `Bad credentials list`).
* Updated deprecated imports from `ansible.module_utils._text` to `ansible.module_utils.common.text.converters` in all modules (the `_text` alias is removed in ansible-core 2.24).
* Excluded developer files (`.claude`, `.github`, `.DS_Store`, `CLAUDE.md`) from the built collection artifact.
* Fixed the `make install` target, which installed a hardcoded `1.0.1` tarball regardless of the collection version.
* Made the `venafi_policy` module idempotent for `state: present`: it now compares the local policy specification against the platform's and only updates when they differ, instead of re-applying (`changed=True`) on every run. The change-detection routine (`policy_utils.check_policy_specification`) was repaired — it previously crashed or reported false differences: elliptic-curve and key-type comparisons are now case-insensitive, list comparisons use exact multiset equality, and NGTS owners/users/approvers (always empty on that platform) are skipped (parity with the Go connector). `state: absent` no longer requires `policy_spec_path` and reports its unsupported-deletion consistently between check mode and apply. Added `venafi_policy` usage examples for Self-Hosted, SaaS, and NGTS. Verified live against Strata Cloud Manager (NGTS) issuing templates.
* `venafi_policy` idempotency also holds for minimal/declarative policy files: any field, list, or nested block the local file omits is treated as "unspecified" and skipped, instead of reporting `changed` on every run (`certificateAuthority` is the deliberate exception — see the next entry). Previously a realistic minimal file (e.g. only `domains` and `keyTypes`, or omitting `maxValidDays` / `ellipticCurves` / the `subject` / `keyPair` / `defaults` blocks) churned forever against a fully-populated platform policy, because omitted scalars and empty lists were compared against the platform's real values. `force: true` remains the escape hatch to re-apply regardless.
* `venafi_policy` compares `certificateAuthority` as the **effective** CA that will be applied. The SDK defaults an omitted CA to the built-in default and sends it, so — matching the vcert Go SDK and `terraform-provider-venafi` declarative model (`BuildCloudCitRequest`) — an omitted or explicitly built-in CA that would reset a real remote CA (e.g. DigiCert → built-in) is now reported as a change and shown in check mode, instead of being silently skipped; it converges after one apply. To keep a non-built-in CA on an existing CIT, set `certificateAuthority` explicitly in the policy file. Live-verified against Strata Cloud Manager (NGTS) DigiCert / ZTPKI / built-in CITs.
* `venafi_policy` now detects drift in `subjectAltNames.uriProtocols` and `subjectAltNames.ipConstraints`. Changing the allowed URI protocols or IP constraints while the corresponding `*_allowed` flag stayed the same was silently missed (`changed=False`), so the update was never applied. URI protocols are matched case-insensitively; both are compared only when the local file declares them (an omitted list does not report a false change).
* `venafi_policy` no longer masks connection/authentication failures as "policy does not exist". A failure while reading the current policy (e.g. a mistyped NGTS `token_url`, bad credentials, or a server error) was swallowed and reported as `Creating policy <zone>` (`changed=True`), hiding the real error and defeating idempotency in check mode. Connection, authentication, and unexpected-server errors now fail the task with a clear message; only a genuine not-found still means the policy will be created.
* `venafi_policy` with `test_mode: true` now fails fast with a clear message instead of aborting with a raw `NotImplementedError` traceback (the fake backend implements no policy operations).
* Stopped emitting the "user/password authentication is deprecated" warning on every SaaS/Self-Hosted run that uses only a token or access token. The warning now fires only when `user` or `password` is actually supplied.

##### 1.3.1
* Bumped the `vcert` dependency to `vcert>=0.21.1` in `requirements.in` and regenerated the hash-pinned `requirements.txt` lockfile (`vcert==0.21.1`). `vcert` 0.21.1 fixes service-generated CSR (`csr_origin: service`) enrollment on CyberArk Certificate Manager, Self-Hosted (TPP): the requested key specification (key type and size, e.g. RSA 4096) is now sent on the enrollment request, so TPP no longer silently falls back to the policy-folder default key size. This resolves the `Private key file does not contain a valid private key` failure in the `venafi_certificate` module that occurred when `privatekey_size` did not match the policy default (surfaced after upgrading to TPP 25.1+/25.3). Delivered entirely through the updated `vcert` SDK — no collection code changes.

##### 1.3.0
* Added the `venafi_certificate_revoke` module to revoke a certificate on CyberArk Certificate Manager, Self-Hosted (TPP), SaaS, and NGTS (Strata Cloud Manager). Self-Hosted (TPP) revokes by certificate DN (`certificate_dn`) or SHA-1 `thumbprint` and honors retire/`no_retire`; SaaS and NGTS revoke by SHA-1 `thumbprint` (the DN and the `ca-compromise` reason are not supported, and `no_retire` is ignored). The reason vocabulary matches the Go `vcert revoke` command (`none`, `key-compromise`, `ca-compromise`, `affiliation-changed`, `superseded`, `cessation-of-operation`). Revocation is imperative: the module always attempts to revoke and the inherited `state` option is accepted but ignored.
* Bumped the `vcert` dependency to `vcert>=0.21.0` in `requirements.in` and regenerated the hash-pinned `requirements.txt` lockfile. SaaS and NGTS certificate revocation is only available in `vcert` 0.21.0; Self-Hosted (TPP) revocation also works on earlier releases.

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
