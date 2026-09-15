import unittest

from plugins.module_utils.common_utils import (
    get_revocation_reason,
    VenafiAnsibleError,
)
from plugins.modules import venafi_certificate_revoke as revoke_mod
from plugins.modules.venafi_certificate_revoke import VCertificateRevoke


class Fail(Exception):
    pass


def base_params(**overrides):
    """Build a full module.params dict (every key the revoke module + get_venafi_connection read)."""
    params = {
        # connection / backend-selection params
        'test_mode': False,
        'url': None,
        'user': None,
        'password': None,
        'token': None,
        'access_token': None,
        'trust_bundle': None,
        'client_id': None,
        'client_secret': None,
        'token_url': None,
        'tsg_id': None,
        'scope': None,
        # revocation params
        'thumbprint': None,
        'certificate_dn': None,
        'reason': 'none',
        'comments': 'revocation request from Ansible',
        'ca_account_name': None,
        'no_retire': False,
    }
    params.update(overrides)
    return params


class FakeModule(object):
    def __init__(self, params):
        self.params = params
        self.warnings = []
        self.fail_code = None
        self.exit_code = None

    def warn(self, msg):
        self.warnings.append(msg)

    def fail_json(self, **kwargs):
        self.fail_code = kwargs
        raise Fail(kwargs.get('msg'))

    def exit_json(self, **kwargs):
        self.exit_code = kwargs


class RecordingConnector(object):
    """Stand-in for a vcert connection that records the RevocationRequest it received."""
    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.revoked = None

    def revoke_cert(self, request):
        self.revoked = request
        if self.exc is not None:
            raise self.exc
        return self.response


class _PatchConnection(object):
    """Patch the connection factory the revoke module uses so no network is touched."""
    def setUp(self):
        self.connector = RecordingConnector()
        self._orig = revoke_mod.get_venafi_connection
        revoke_mod.get_venafi_connection = lambda module: self.connector

    def tearDown(self):
        revoke_mod.get_venafi_connection = self._orig

    def build(self, **params):
        module = FakeModule(base_params(**params))
        vcert = VCertificateRevoke(module)
        return module, vcert


class TestGetRevocationReason(unittest.TestCase):
    def test_known_reasons_map_to_sdk_codes(self):
        self.assertEqual(get_revocation_reason('none'), 0)
        self.assertEqual(get_revocation_reason('key-compromise'), 1)
        self.assertEqual(get_revocation_reason('ca-compromise'), 2)
        self.assertEqual(get_revocation_reason('affiliation-changed'), 3)
        self.assertEqual(get_revocation_reason('superseded'), 4)
        self.assertEqual(get_revocation_reason('cessation-of-operation'), 5)

    def test_empty_reason_is_no_reason(self):
        self.assertEqual(get_revocation_reason(None), 0)
        self.assertEqual(get_revocation_reason(''), 0)

    def test_unknown_reason_raises(self):
        self.assertRaises(VenafiAnsibleError, get_revocation_reason, 'not-a-reason')


@unittest.skipUnless(revoke_mod.HAS_VCERT, "vcert SDK not installed")
class TestBuildRequestTpp(unittest.TestCase, _PatchConnection):
    setUp = _PatchConnection.setUp
    tearDown = _PatchConnection.tearDown

    def test_dn_path_retires_by_default(self):
        dummy, vcert = self.build(url='https://tpp', access_token='tok', certificate_dn='\\VED\\Policy\\example\\cert')
        self.assertEqual(vcert.request.id, '\\VED\\Policy\\example\\cert')
        self.assertIsNone(vcert.request.thumbprint)
        self.assertTrue(vcert.request.disable)

    def test_dn_path_no_retire_keeps_object(self):
        dummy, vcert = self.build(url='https://tpp', access_token='tok', certificate_dn='\\VED\\Policy\\example\\cert', no_retire=True)
        self.assertFalse(vcert.request.disable)

    def test_thumbprint_path_never_retires(self):
        dummy, vcert = self.build(url='https://tpp', access_token='tok', thumbprint='AA:BB', no_retire=True)
        self.assertEqual(vcert.request.thumbprint, 'AA:BB')
        self.assertIsNone(vcert.request.id)
        self.assertFalse(vcert.request.disable)

    def test_reason_is_mapped_to_int_code(self):
        dummy, vcert = self.build(url='https://tpp', access_token='tok', thumbprint='AA:BB', reason='superseded')
        self.assertEqual(vcert.request.reason, 4)

    def test_ca_compromise_allowed_for_tpp(self):
        dummy, vcert = self.build(url='https://tpp', access_token='tok', thumbprint='AA:BB', reason='ca-compromise')
        self.assertEqual(vcert.request.reason, 2)

    def test_comments_passed_through(self):
        dummy, vcert = self.build(url='https://tpp', access_token='tok', thumbprint='AA:BB', comments='decommissioned host')
        self.assertEqual(vcert.request.comments, 'decommissioned host')


@unittest.skipUnless(revoke_mod.HAS_VCERT, "vcert SDK not installed")
class TestBuildRequestCloudNgts(unittest.TestCase, _PatchConnection):
    setUp = _PatchConnection.setUp
    tearDown = _PatchConnection.tearDown

    def test_cloud_requires_thumbprint(self):
        module = FakeModule(base_params(token='apikey', certificate_dn='some-dn'))
        self.assertRaises(Fail, VCertificateRevoke, module)
        self.assertIn('thumbprint', module.fail_code['msg'])

    def test_cloud_rejects_ca_compromise(self):
        module = FakeModule(base_params(token='apikey', thumbprint='AA:BB', reason='ca-compromise'))
        self.assertRaises(Fail, VCertificateRevoke, module)
        self.assertIn('ca-compromise', module.fail_code['msg'])

    def test_ngts_requires_thumbprint(self):
        module = FakeModule(base_params(client_id='cid', client_secret='sec', tsg_id='1',
                                        certificate_dn='some-dn'))
        self.assertRaises(Fail, VCertificateRevoke, module)
        self.assertIn('thumbprint', module.fail_code['msg'])

    def test_ngts_rejects_ca_compromise(self):
        module = FakeModule(base_params(client_id='cid', client_secret='sec', tsg_id='1',
                                        thumbprint='AA:BB', reason='ca-compromise'))
        self.assertRaises(Fail, VCertificateRevoke, module)
        self.assertIn('ca-compromise', module.fail_code['msg'])

    def test_cloud_thumbprint_ok_and_disable_false(self):
        dummy, vcert = self.build(token='apikey', thumbprint='AA:BB', reason='key-compromise')
        self.assertEqual(vcert.request.thumbprint, 'AA:BB')
        self.assertFalse(vcert.request.disable)
        self.assertEqual(vcert.request.reason, 1)

    def test_ca_account_name_set_when_provided(self):
        dummy, vcert = self.build(token='apikey', thumbprint='AA:BB', ca_account_name='DigiCert')
        self.assertEqual(getattr(vcert.request, 'ca_account_name', None), 'DigiCert')

    def test_no_retire_warns_but_does_not_fail(self):
        module, vcert = self.build(token='apikey', thumbprint='AA:BB', no_retire=True)
        self.assertIsNone(module.fail_code)
        self.assertTrue(any('no_retire' in w for w in module.warnings))


@unittest.skipUnless(revoke_mod.HAS_VCERT, "vcert SDK not installed")
class TestRevokeAndDump(unittest.TestCase, _PatchConnection):
    setUp = _PatchConnection.setUp
    tearDown = _PatchConnection.tearDown

    def test_cloud_structured_dump(self):
        self.connector.response = {
            'id': 'cert-123', 'thumbprint': 'AA:BB', 'serial': '0F:1E',
            'status': 'SUBMITTED', 'rejection_reason': None,
        }
        dummy, vcert = self.build(token='apikey', thumbprint='AA:BB')
        vcert.revoke()
        result = vcert.dump()
        self.assertTrue(result['changed'])
        self.assertEqual(result['certificate_id'], 'cert-123')
        self.assertEqual(result['thumbprint'], 'AA:BB')
        self.assertEqual(result['serial'], '0F:1E')
        self.assertEqual(result['status'], 'SUBMITTED')
        self.assertNotIn('rejection_reason', result)  # None -> omitted

    def test_cloud_rejection_reason_reported(self):
        self.connector.response = {
            'id': 'cert-123', 'thumbprint': 'AA:BB', 'serial': None,
            'status': 'REJECTED_APPROVAL', 'rejection_reason': 'Not authorized',
        }
        dummy, vcert = self.build(token='apikey', thumbprint='AA:BB')
        vcert.revoke()
        result = vcert.dump()
        self.assertEqual(result['status'], 'REJECTED_APPROVAL')
        self.assertEqual(result['rejection_reason'], 'Not authorized')

    def test_tpp_raw_body_dump(self):
        self.connector.response = {'CertificateDN': '\\VED\\Policy\\x', 'Requested': True}
        dummy, vcert = self.build(url='https://tpp', access_token='tok', certificate_dn='\\VED\\Policy\\x')
        vcert.revoke()
        result = vcert.dump()
        self.assertTrue(result['changed'])
        self.assertEqual(result['revocation_details'], {'CertificateDN': '\\VED\\Policy\\x', 'Requested': True})

    def test_not_implemented_gives_version_hint(self):
        self.connector.exc = NotImplementedError()
        module, vcert = self.build(token='apikey', thumbprint='AA:BB')
        self.assertRaises(Fail, vcert.revoke)
        self.assertIn('0.21.0', module.fail_code['msg'])

    def test_generic_error_is_wrapped(self):
        self.connector.exc = Exception('backend boom')
        module, vcert = self.build(url='https://tpp', access_token='tok', thumbprint='AA:BB')
        self.assertRaises(Fail, vcert.revoke)
        self.assertIn('Failed to revoke certificate', module.fail_code['msg'])
        self.assertIn('backend boom', module.fail_code['msg'])

    def test_check_is_side_effect_free(self):
        # check() must not touch the backend (this is what guarantees safe check-mode).
        dummy, vcert = self.build(url='https://tpp', access_token='tok', thumbprint='AA:BB')
        result = vcert.check()
        self.assertTrue(result['changed'])
        self.assertIn('AA:BB', result['changed_msg'])
        self.assertIsNone(self.connector.revoked)


if __name__ == '__main__':
    unittest.main()
