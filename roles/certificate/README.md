![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi `certificate` Role for Ansible

This role adds certificate enrollment capabilities to [Red Hat Ansible](https://www.ansible.com/) by seamlessly
integrating with the [Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform)
or [Venafi as a Service](https://vaas.venafi.com/) in a manner that ensures compliance with corporate
security policy and provides visibility into certificate issuance enterprise wide.

>:red_car: **Test drive our integration examples today**
>
>Let us show you _step-by-step_ how to add certificates to your _Infrastucture as Code_ automation with Ansible.
>
>Products | Available integration examples...
>:------: | --------
>[<img src="examples/logo_tile_f5.png?raw=true" alt="F5 BIG-IP" width="40" height="40" />](examples/f5_bigip/README.md) | [How to configure secure application delivery using F5 BIG-IP and the Venafi Role Ansible](examples/f5_bigip/README.md)
>[<img src="examples/logo_tile_citrix.png?raw=true" alt="Citrix ADC" width="40" height="40" />](examples/citrix_adc/README.md)  | [How to configure secure application delivery using Citrix ADC and the Venafi Role for Ansible](examples/citrix_adc/README.md)
>[<img src="examples/logo_tile_iis.png?raw=true" alt="Microsoft IIS" width="40" height="40" />](examples/microsoft_iis/README.md)  | [How to secure and configure Microsoft IIS using the Venafi Role for Ansible](examples/microsoft_iis/README.md)
>
>**NOTE** If you don't see an example for a product you use, check back later. We're working hard to add more integration examples.

## Requirements

Review the [Venafi](https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform)
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

2. Create the `credentials.yml` and populate it with connection parameters:

   **Trust Protection Platform**:
   
   ```sh
   cat <<EOF >>credentials.yml
   access_token: 'p0WTt3sDPbzm2BDIkoJROQ=='
   url: 'https://tpp.venafi.example'
   zone: "DevOps\\Ansible"
   trust_bundle: "/path/to/bundle.pem"
   EOF
   ```

   **Venafi as a Service**:
   
   ```sh
   cat <<EOF >>credentials.yml
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **Venafi as a Service EU**:
   
   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.venafi.eu'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```
   
   **Venafi as a Service AU**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.au.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **Venafi as a Service UK**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.uk.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **Venafi as a Service SG**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.sg.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   **Venafi as a Service CA**:

   ```sh
   cat <<EOF >>credentials.yml
   url: 'https://api.ca.venafi.cloud'
   token: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
   zone: 'Business App\\Enterprise CIT'
   EOF
   ```

   The certificate role supports the following connection and credential settings:
   
   | Variable Name  | Description                                                  |
   | -------------- | ------------------------------------------------------------ |
   | `access_token` | Trust Protection Platform access token for the "ansible-by-venafi" API Application |
   | `password`     | **[DEPRECATED]** Trust Protection Platform WebSDK password, use `access_token` if possible |
   | `test_mode`    | When "true", the role operates without connecting to Trust Protection Platform or Venafi as a Service |
   | `token`        | Venafi as a Service API key                                         |
   | `trust_bundle` | Text file containing trust anchor certificates in PEM (text) format, generally required for Trust Protection Platform |
   | `url`          | Venafi service URL (e.g. "https://tpp.venafi.example") |
   | `user`         | **[DEPRECATED]** Trust Protection Platform WebSDK username, use `access_token` if possible |
   | `zone`         | Policy folder for TPP or Application name and Issuing Template API Alias for VaaS (e.g. "Business App\Enterprise CIT") |

3. Use `ansible-vault` to encrypt the `credentials.yml` file using a password.  This is optional but highly recommended.
   As long as you know the password you can always decrypt the file to make changes and then re-encrypt it.
   Go to https://docs.ansible.com/ansible/latest/user_guide/vault.html for more information.

   ```sh
   ansible-vault encrypt credentials.yml
   ```

4. Write a simple playbook called, for example, `sample.yml`.

   ```yaml
   - hosts: localhost
     roles:
       - role: venafi.machine_identity.certificate
         certificate_common_name: "certificate.example.com" 
         certificate_cert_dir: "/tmp/etc/ssl"
   ```

5. Run the playbook.

   ```sh
   ansible-playbook sample.yml --ask-vault-pass
   ```
   
   Running the playbook will generate a certificate and place it into folder in /tmp/etc/ssl/ directory.
   The `--ask-vault-pass` parameter is needed if you encrypted the `credentials.yml` file.
   
6. Additional playbook variables can be added to specify properties of the certificate and key pair, file locations, 
   and to override default behaviors.
   
   ```sh
   cat variables.yml
   ```
   The following is the list of variables accepted by the certificate role: 

   | Variable Name                            | Description                                                  |
   | ---------------------------------------- | ------------------------------------------------------------ |
   | `credentials_file`                       | Name of the file containing Venafi credentials and connection settings<br/>Default: `credentials.yml` |
   | `certificate_alt_name`                   | Comma separated list of *Subject Alternative Names* to request for the certificate.  Prefix each value with the SAN type.<br/>Example: `"DNS:host.example.com,IP:10.20.30.40,email:me@example.com"` |                                                              |
   | `certificate_before_expired_hours`       | Number of hours prior to the expiration of the certificate before it can be renewed<br/>Default: `72` |
   | `certificate_cert_dir`                   | Local parent directory where the cryptographic assets will be stored<br/>Default: `"/etc/ssl/{{ certificate_common_name }}"` |
   | `certificate_cert_path`                  | Local directory where certificate files will be stored<br/>Default: `{{ certificate_cert_dir }}/{{ certificate_common_name }}.pem"` |
   | `certificate_chain_option`               | Specifies whether the root CA certificate appears `"last"` (default) or `"first"` in the chain file |
   | `certificate_chain_path`                 | Local directory where certificate chain files will be stored<br/>Default: `"{{ certificate_cert_dir }}/{{ certificate_common_name }}.chain.pem"` |
   | `certificate_common_name`                | *Common Name* to request for the certificate.<br/>Default: `"{{ ansible_fqdn }}"` |
   | `certificate_copy_private_key_to_remote` | Specifies whether to copy the private key file to the remote host<br/>Default: `true` |
   | `certificate_csr_origin`                 | Specifies the source of the CSR used to request a certificate. <br/>Default: `"local"` <br/>Options: `"local"` - Generates CSR locally, `"provided"` - CSR is provided, or `"service"` - Venafi generates CSR |
   | `certificate_csr_path`                   | Local directory where certificate signing request files will be stored<br/>Default: `"{{ certificate_cert_dir }}/{{ certificate_common_name }}.csr"` |
   | `certificate_custom_fields`              | Map of custom-defined attributes for the certificate, declared as key-value format. Example: <pre lang="yaml">certificate_custom_fields:<br/>  custom: asd<br/>  cfList: item3<br/>  cfListMulti: [tier1, tier4]</pre> |
   | `certificate_force`                      | Specifies whether to request a new certificate every time the playbook is run<br/>Default: `false` |
   | `certificate_issuer_hint`                | Issuer of the certificate. Ignored when platform is not TPP.<br/>Use in combination with `validity_hours` to specify the validity period of a certificate on TPP.<br/>Default: `"DEFAULT"`<br/>Options: `"DEFAULT"`, `"DIGICERT"`, `"ENTRUST"`, or `"MICROSOFT"` |
   | `certificate_pkcs12_format`              | Use PKCS12 format to serialize the certificate.<br/>Default: `false` |
   | `certificate_privatekey_curve`           | Elliptic Curve for ECDSA keys<br/>Default: `"P256"` (from VCert) | 
   | `certificate_privatekey_passphrase`      | Password to use for encrypting the private key |
   | `certificate_privatekey_path`            | Local directory where private key files will be stored<br/>Default: `"{{ certificate_cert_dir }}/{{ certificate_common_name }}.key"` |
   | `certificate_privatekey_size`            | Key size in bits for RSA keys<br/>Default: `"2048"` (from VCert) <br/>Options: `"1024"`, `"2048"` or `"4096"`|
   | `certificate_privatekey_type`            | Key algorithm <br/>Default: `"RSA"` (from VCert) <br/>Options: `"RSA"` or `"ECDSA"`|
   | `certificate_remote_cert_path`           | Directory on remote host where certificate files will be stored<br/>Default: `"{{ certificate_cert_dir }}/{{ certificate_common_name }}.pem"` |
   | `certificate_remote_chain_path`          | Directory on remote host where certificate chain files will be stored<br/>Default: `"{{ certificate_cert_dir }}/{{ certificate_common_name }}.chain.pem"` |
   | `certificate_remote_execution`           | Specifies whether cryptographic assets will be generated remotely, or locally and then provisioned to the remote host<br/>Default: `false` | 
   | `certificate_remote_privatekey_path`     | Directory on remote host where private key files will be stored<br/>Default: `"{{ certificate_cert_dir }}/{{ certificate_common_name }}.key"` |
   | `certificate_renew`                      | Specifies whether to renew the certificate if it is within the "before_expired_hours" window when the playbook is run<br/>Default: `true` |
   | `certificate_validity_hours`             | Indicates the validity period of the certificate before it expires |

   Defaults are defined in the [defaults/main.yml](defaults/main.yml) file.

## Preparing a Docker demo environment for running Ansible 

1. For this demo, move to the root folder of this collection.
1. Prepare the demo environment.  If you want to use your own inventory, update the [tests/certificate/inventory](../../tests/certificate/inventory) file.  

    1. To run our test/demo playbook you'll need the Docker provisioning role.
       Download it into the `/tests/certificate/roles/provision_docker` directory: 
       
       ```sh
       git clone https://github.com/chrismeyersfsu/provision_docker.git tests/certificate/roles/provision_docker
       ```
        
    1. Then build the Docker images needed for the demo playbook:
    
       ```sh
       docker build ./tests/certificate --tag certificate-local-ansible-test
       ```
    
    Demo certificates will be placed in the `/tmp/ansible/etc/ssl` directory on the Ansible host.
    From there they will be distributed to the `/etc/ssl/` directory of remote hosts.
    
1. Generate a credentials file for either Trust Protection Platform or Venafi as a Service as described in the above section.  
    
1. Run the Ansible playbook (remove `docker_demo=true` if you want to use your own inventory).
   The contents of `credentials.yml` will be used to decide whether Trust Protection Platform or Venafi as a Service is used. 
   If you set the `token` parameter, the playbook assumes you are using Venafi as a Service.  If you set the `access_token` or
   `password` parameters, the playbook assumes you are using Trust Protection Platform.
   
   ```sh
   cd ./tests/certificate
   ansible-playbook -i inventory \
     venafi-playbook-example.yml \
     --extra-vars "credentials_file=credentials.yml docker_demo=true" \
     --ask-vault-pass
   ```
   
   You will be prompted for the password for decrypting the `credentials.yml` as before.  The source file for the
   credentials can be overridden using the *credentials_file* variable and this can be specified on the command line
   using the `--extra-vars` parameter as shown. 

## Sample Playbook

```yaml
- hosts: servers
  roles:
    - role: "venafi.machine_identity.certificate"
      certificate_common_name: "{{ ansible_fqdn }}.venafi.example.com"
      certificate_cert_dir: "/tmp/ansible/etc/ssl/{{ certificate_common_name }}"
      certificate_cert_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.pem"
      certificate_chain_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.chain.pem"
      certificate_privatekey_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.key"
      certificate_csr_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.csr"

      # Where to execute venafi_certificate module. If set to false, certificate will be
      # created on ansible master host and then copied to the remote server.
      certificate_remote_execution: false
      # Remote location where to place the certificate.
      certificate_remote_cert_dir: "/etc/ssl"
      certificate_remote_cert_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.pem"
      certificate_remote_chain_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.chain.pem"
      certificate_remote_privatekey_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.key"
      # Set to false if you don't want to copy private key to remote location.
      certificate_copy_private_key_to_remote: true
```

For playbook examples look into [venafi-playbook-example.yml](../../tests/certificate/venafi-playbook-example.yml) file.
For role examples look into [venafi-role-playbook-example.yml](../../tests/certificate/venafi-role-playbook-example.yml) file

For more information about using roles go to https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Apache License, Version 2.0. See [`LICENSE`](../../LICENSE) for the full license text.

Please direct questions/comments to opensource@venafi.com.
