FROM python:3.6.8

WORKDIR /usr/src/app

RUN ["bash", "-c", "pip install -U pip"]
RUN ["bash", "-c", "pip install ansible"]
RUN ["bash", "-c", "pip install vcert"]
RUN ["bash", "-c", "ansible-galaxy collection install venafi.machine_identity"]

COPY ./test ./test

CMD ["bash"]