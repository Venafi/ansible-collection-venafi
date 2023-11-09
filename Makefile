pep8:
	# Ansible galaxy requires that the doc strings are at the top of the file.
	# E402 is the error for imports not being at top. Ignoring per ansible requirement.
	# Max line length set to 120 as it is PyCharm default (current IDE)
	pycodestyle --first --max-line-length=120 --ignore=E402 ./plugins

yamllint:
	yamllint `git ls-files '*.yml' | grep -v ISSUE_TEMPLATE`

lint: lint-certificate lint-policy lint-ssh-ca lint-ssh-certificate

lint-certificate: yamllint pep8
	# Certificate role
	ansible-lint -x 106,204,504 ./roles/certificate/tasks/*
	ansible-lint ./roles/certificate/meta/*
	ansible-lint ./roles/certificate/defaults/*

lint-policy: yamllint pep8
	# Policy role
	ansible-lint -x 106,204,504 ./roles/policy/tasks/*
	ansible-lint ./roles/policy/meta/*
	ansible-lint ./roles/policy/defaults/*

lint-ssh-ca: yamllint pep8
	# SSH_CA role
	ansible-lint -x 106,204,504 ./roles/ssh_ca/tasks/*
	ansible-lint ./roles/ssh_ca/meta/*
	ansible-lint ./roles/ssh_ca/defaults/*

lint-ssh-certificate: yamllint pep8
	# SSH_Certificate role
	ansible-lint -x 106,204,504 ./roles/ssh_certificate/tasks/*
	ansible-lint ./roles/ssh_certificate/meta/*
	ansible-lint ./roles/ssh_certificate/defaults/*

ansible-molecule:
	docker build ./tests --tag local-ansible-test
	ANSIBLE_VAULT_PASSWORD_FILE=${PWD}/vault-password.txt molecule converge

# Testing ansible crypto modules for examples and compability checks
#test-crypto-playbook:
#	ansible-playbook -i tests/certificate/inventory tests/certificate/original-ansible-crypto-playbook-example.yml

# Test Ansible playbook with venafi certificate module

#test-vcert-playbook-tpp:
#	# Have to copy library to test our module, otherwise test playbook will not
#	docker build ./tests --tag local-ansible-test
#	rm -rvf tests/library
#	cp -rv plugins/modules/venafi_certificate.py tests/library
#	ansible-playbook -i tests/inventory tests/certificate/venafi-playbook-example.yml \
#	--vault-password-file vault-password.txt \
#	--extra-vars "credentials_file=./tpp_credentials.yml docker_demo=true"

# Test Ansible role with venafi_Certificate module

#test-vcert-role-tpp:
#	# Have to copy library to test our module, otherwise test playbook will not
#	docker build ./tests --tag local-ansible-test
#	rm -rvf tests/library
#	cp -rv plugins/modules/venafi_certificate.py tests/
#	ansible-playbook -i tests/inventory tests/venafi-role-playbook-example.yml \
#	--vault-password-file vault-password.txt \
#	--extra-vars "credentials_file=tpp_credentials.yml docker_demo=true"

#test-vcert-role-cloud:
#	# Have to copy library to test our module, otherwise test playbook will not
#	docker build ./tests --tag local-ansible-test
#	rm -rvf tests/library
#	cp -rv library tests/
#	ansible-playbook -i tests/inventory tests/venafi-role-playbook-example.yml \
#	--vault-password-file vault-password.txt \
#	--extra-vars "credentials_file=cloud_credentials.yml docker_demo=true"

#test-vcert-role-fake:
#	# Have to copy library to test our module, otherwise test playbook will not
#	docker build ./tests --tag local-ansible-test
#	rm -rvf tests/library
#	cp -rv library tests/
#	ansible-playbook -i tests/inventory tests/venafi-role-playbook-example.yml \
#	--vault-password-file vault-password.txt \
#	--extra-vars "credentials_file=fake_credentials.yml docker_demo=true"

unit-test:
	PYTHONPATH=./:$PYTHONPATH pytest ./tests/certificate/test_venafi_certificate.py

install:
	ansible-galaxy collection build --force
	ansible-galaxy collection install venafi-machine_identity-1.0.1.tar.gz --force

uninstall:
	rm -rf ~/.ansible/collections/ansible_collections/venafi
