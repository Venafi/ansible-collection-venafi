"""
Test-only shim: make vcert's FakeConnection (``test_mode: true``) handle a user-provided CSR the way
the real connectors do.

The real connectors (CloudConnection / NGTS, AbstractTPPConnection) return ``cert.key = None`` when
the request carries no private key (``csr_origin: provided``). The stock FakeConnection instead
serializes ``request.private_key`` unconditionally and crashes with an AttributeError, so the
provided-CSR path of ``venafi_certificate`` cannot be exercised offline without this shim.

Activation: put this directory first on PYTHONPATH of the process that runs the module, e.g. an
ansible task ``environment: {PYTHONPATH: <this dir>}`` (reaches the AnsiballZ subprocess) or the
``env`` of a standalone module subprocess. Python imports ``sitecustomize`` at startup.

Optional: set ``VENAFI_FAKE_ISSUE_LOG=<file>`` to append one line per issued certificate, so a test
can count issuances (a provided CSR that re-enrolls on every run shows up as extra lines).
"""
import os

try:
    from vcert.connection_fake import FakeConnection
except ImportError:  # vcert not importable in this interpreter: nothing to patch
    FakeConnection = None


class _NoKeyRequest(object):
    """Read-through view of a CertificateRequest whose private key is absent."""
    private_key_pem = None

    def __init__(self, request):
        self._request = request

    def __getattr__(self, name):
        return getattr(self._request, name)


if FakeConnection is not None and not getattr(FakeConnection, "_venafi_smoke_shim", False):
    _orig_retrieve_cert = FakeConnection.retrieve_cert

    def _retrieve_cert(self, certificate_request):
        if certificate_request.private_key is None:
            # provided CSR: sign it, but return no key (connection_cloud.py / connection_tpp_abstract.py)
            response = _orig_retrieve_cert(self, _NoKeyRequest(certificate_request))
        else:
            response = _orig_retrieve_cert(self, certificate_request)
        log = os.environ.get("VENAFI_FAKE_ISSUE_LOG")
        if log:
            with open(log, "a") as fh:
                fh.write("%s\n" % certificate_request.common_name)
        return response

    FakeConnection.retrieve_cert = _retrieve_cert
    FakeConnection._venafi_smoke_shim = True
