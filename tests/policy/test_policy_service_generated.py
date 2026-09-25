"""
Offline round-trip tests for the serviceGenerated comparison in policy_utils.check_policy_specification.

Unlike test_policy_utils.py (hand-built specs), these drive the REAL vcert converters end to end:
a real NGTSConnection / TPPTokenConnection runs its own get_policy (build_policy_spec /
TPPPolicy.to_policy_spec) and set_policy (build_cit_request / TPPPolicy.build_tpp_policy); only the
HTTP verbs (_get/_put/_post/get) are replaced by a tiny in-memory server that stores what set_policy
sends and echoes it back on the next read. Each case checks: before apply -> changed exactly when the
remote differs; after one apply -> unchanged (convergence, no perpetual drift).

Cloud/NGTS: get_policy returns policy.keyPair.serviceGenerated=None when the CIT allows BOTH CSR upload
and service-generated keys; None must not be coerced to False (finding M27). TPP: get_policy drops a
user-provided (false) CsrGeneration and reports a service-generated one as policy.keyPair (locked) or
defaults.keyPair (unlocked), so an explicit false must be checked against both blocks.
"""
import copy
import unittest

from vcert.connection_ngts import NGTSConnection
from vcert.connection_tpp_abstract import URLS as TPP_URLS
from vcert.connection_tpp_token import TPPTokenConnection
from vcert.connection_cloud import URLS as CLOUD_URLS
from vcert.parser.utils import parse_data

from plugins.module_utils.policy_utils import check_policy_specification

ZONE = 'Default'
CA_ACCOUNT_ID = 'acct-1'
PRODUCT_OPTION_ID = 'po-1'
CA_ACCOUNT = {
    'account': {'id': CA_ACCOUNT_ID, 'key': 'Built-In CA', 'certificateAuthority': 'BUILTIN'},
    'productOptions': [{'productName': 'Default Product', 'id': PRODUCT_OPTION_ID,
                        'productDetails': {'productTemplate': {'organizationId': None}}}],
}
# (csrUploadAllowed, keyGeneratedByVenafiAllowed) -> serviceGenerated as read back by get_policy
CIT_MODES = {
    'csr-only': (True, False),        # -> False (also the NGTS 'Default' CIT shape)
    'service-only': (False, True),    # -> True
    'both': (True, True),             # -> None
}


def ngts_cit(csr_upload, key_gen, recommended_key=False):
    """A CIT JSON shaped like the NGTS 'Default' template (Built-In CA, RSA 2048 only)."""
    cit = {
        'id': 'cit-1', 'name': ZONE, 'certificateAuthority': 'BUILTIN',
        'certificateAuthorityAccountId': CA_ACCOUNT_ID, 'certificateAuthorityProductOptionId': PRODUCT_OPTION_ID,
        'subjectCNRegexes': ['.*'], 'sanRegexes': ['.*'], 'subjectORegexes': ['.*'],
        'subjectOURegexes': ['.*'], 'subjectLRegexes': ['.*'], 'subjectSTRegexes': ['.*'],
        'subjectCValues': ['.*'], 'keyTypes': [{'keyType': 'RSA', 'keyLengths': [2048]}],
        'keyReuse': False, 'validityPeriod': 'P365D',
        'csrUploadAllowed': csr_upload, 'keyGeneratedByVenafiAllowed': key_gen,
    }
    if recommended_key:
        cit['recommendedSettings'] = {'key': {'type': 'RSA', 'length': 2048}}
    return cit


class FakeNgts(object):
    """Real NGTSConnection whose HTTP verbs hit an in-memory CIT store (no network, no token)."""

    def __init__(self, cit):
        self.cit = cit
        self.puts = []
        self.conn = NGTSConnection(client_id='id', client_secret='secret', tsg_id='1234567890',
                                   token_url='https://auth.apps.paloaltonetworks.com/oauth2/access_token',
                                   url='https://api.example.com/ngts', access_token='t')
        self.conn._get = self._get
        self.conn._put = self._put
        self.conn._post = self._post

    def _get(self, url, params=None):
        if url == CLOUD_URLS.ISSUING_TEMPLATES:
            return 200, {'certificateIssuingTemplates': [copy.deepcopy(self.cit)]}
        if url == CLOUD_URLS.CA_ACCOUNT_DETAILS.format('BUILTIN', CA_ACCOUNT_ID):
            return 200, copy.deepcopy(CA_ACCOUNT)
        if url == CLOUD_URLS.CA_ACCOUNTS.format('BUILTIN'):
            return 200, {'accounts': [copy.deepcopy(CA_ACCOUNT)]}
        raise AssertionError('unexpected GET %s' % url)

    def _put(self, url, data=None):
        assert url == CLOUD_URLS.ISSUING_TEMPLATES_UPDATE.format(self.cit['id']), url
        self.puts.append(copy.deepcopy(data))
        # The server replaces the template with the request (keeping its id and the CA account it
        # derives from the product option); the validity period is echoed back at the top level.
        cit = {'id': self.cit['id'], 'certificateAuthorityAccountId': CA_ACCOUNT_ID}
        for key, value in data.items():
            if key == 'product':
                cit['validityPeriod'] = value['validityPeriod']
            else:
                cit[key] = copy.deepcopy(value)
        self.cit = cit
        return 200, copy.deepcopy(self.cit)

    def _post(self, url, data=None):
        raise AssertionError('unexpected POST %s' % url)

    def changed(self, local):
        return check_policy_specification(local, self.conn.get_policy(ZONE), ignore_owners_users=True,
                                          is_tpp=False)

    def apply(self, local):
        self.conn.set_policy(ZONE, copy.deepcopy(local))


def cloud_local(sg, defaults_sg=None):
    kp = {'keyTypes': ['RSA'], 'rsaKeySizes': [2048]}
    if sg is not None:
        kp['serviceGenerated'] = sg
    data = {'policy': {'domains': [], 'keyPair': kp}}
    if defaults_sg is not None:
        data['defaults'] = {'keyPair': {'keyType': 'RSA', 'rsaKeySize': 2048, 'ellipticCurve': None,
                                        'serviceGenerated': defaults_sg}}
    return parse_data(data)


class TestCloudNgtsServiceGenerated(unittest.TestCase):

    def test_m27_explicit_false_vs_both_allowed_cit(self):
        # M27: local serviceGenerated:false vs a CIT that allows CSR upload AND service keys.
        server = FakeNgts(ngts_cit(True, True))
        local = cloud_local(False)
        is_changed, msgs = server.changed(local)
        self.assertTrue(is_changed, 'false vs both-allowed CIT must be reported changed (M27)')
        self.assertEqual(msgs, ['policy.keyPair.serviceGenerated changed. Local: False Remote: None'])
        server.apply(local)
        self.assertEqual(len(server.puts), 1)
        self.assertTrue(server.puts[0]['csrUploadAllowed'])
        self.assertFalse(server.puts[0]['keyGeneratedByVenafiAllowed'])
        self.assertEqual(server.changed(local), (False, []), 'must converge after one apply')

    def test_round_trip_matrix(self):
        # local serviceGenerated {true,false,omitted} (+ false with defaults.keyPair false) x CIT mode.
        remote_sg = {'csr-only': False, 'service-only': True, 'both': None}
        failures = []
        for sg, defaults_sg in ((True, None), (False, None), (None, None), (False, False)):
            local = cloud_local(sg, defaults_sg)
            for mode, (csr_upload, key_gen) in CIT_MODES.items():
                server = FakeNgts(ngts_cit(csr_upload, key_gen, recommended_key=defaults_sg is not None))
                expected = sg is not None and sg != remote_sg[mode]
                cell = 'sg=%s defaults_sg=%s cit=%s' % (sg, defaults_sg, mode)
                before = server.changed(local)
                if before[0] != expected:
                    failures.append('%s before: expected changed=%s got %s' % (cell, expected, before))
                server.apply(local)
                after = server.changed(local)
                if after[0]:
                    failures.append('%s after apply: perpetual drift %s' % (cell, after[1]))
        self.assertEqual(failures, [])

    def test_ngts_default_cit_shape(self):
        # NGTS 'Default' CIT: csrUploadAllowed=True, keyGeneratedByVenafiAllowed=False, Built-In CA,
        # RSA only -> serviceGenerated False.
        server = FakeNgts(ngts_cit(True, False))
        local = cloud_local(False)
        self.assertEqual(server.changed(local), (False, []))
        # Someone widens the template in the UI to allow service-generated keys as well.
        server.cit['keyGeneratedByVenafiAllowed'] = True
        self.assertTrue(server.changed(local)[0], 'widened Default CIT must be reported changed')
        server.apply(local)
        self.assertTrue(server.cit['csrUploadAllowed'])
        self.assertFalse(server.cit['keyGeneratedByVenafiAllowed'])
        self.assertEqual(server.changed(local), (False, []))
        # local true against the Default shape is a genuine change that also converges.
        local_true = cloud_local(True)
        self.assertTrue(server.changed(local_true)[0])
        server.apply(local_true)
        self.assertEqual(server.changed(local_true), (False, []))


# --- Self-Hosted (TPP) ---------------------------------------------------------------------------

POLICY_DN = '\\VED\\Policy\\Certificates\\sg'
MANUAL_CSR = 'Manual Csr'
# Remote CsrGeneration states: (Manual Csr value, Locked) or None when the folder has no value.
TPP_STATES = {
    'user-locked': ('1', True),
    'service-locked': ('0', True),
    'service-unlocked': ('0', False),
    'user-unlocked': ('1', False),
    'absent': None,
}


class FakeTpp(object):
    """Real TPPTokenConnection whose HTTP verbs hit an in-memory policy folder (attribute store)."""

    def __init__(self):
        self.attrs = {}
        self.conn = TPPTokenConnection(url='https://tpp.example.com', access_token='t')
        self.conn._post = self._post
        self.conn.get = self._get

    def _get(self, args):
        assert args[self.conn.ARG_URL] == TPP_URLS.VERSION
        return 200, {'Version': '24.1.0.0'}

    def _post(self, url=None, data=None, check_token=True, include_token_header=True):
        if url == TPP_URLS.POLICY_IS_VALID:
            return 200, {'Result': 1, 'Object': {'TypeName': 'Policy'}}
        if url == TPP_URLS.ZONE_CONFIG:
            return 200, {'Error': None, 'Policy': self._check_policy()}
        if url == TPP_URLS.POLICY_SET_ATTRIBUTE:
            self.attrs[data['AttributeName']] = (data['Values'], data['Locked'])
            return 200, {'Result': 1}
        if url == TPP_URLS.POLICY_CLEAR_ATTRIBUTE:
            self.attrs.pop(data['AttributeName'], None)
            return 200, {'Result': 1}
        if url == TPP_URLS.FIND_POLICY:
            return 200, {'Values': []}
        raise AssertionError('unexpected POST %s' % url)

    def _check_policy(self):
        """Render the stored attributes the way certificates/checkpolicy reports them."""
        policy = {'Subject': {}, 'KeyPair': {}, 'WildcardsAllowed': True}
        for name in ('Organization', 'City', 'State', 'Country'):
            if name in self.attrs:
                values, locked = self.attrs[name]
                policy['Subject'][name] = {'Value': values[0], 'Locked': locked}
        for name, key in (('Key Algorithm', 'KeyAlgorithm'), ('Key Bit Strength', 'KeySize'),
                          ('Elliptic Curve', 'EllipticCurve')):
            if name in self.attrs:
                values, locked = self.attrs[name]
                policy['KeyPair'][key] = {'Value': values[0], 'Locked': locked}
        if MANUAL_CSR in self.attrs:
            values, locked = self.attrs[MANUAL_CSR]
            value = 'UserProvided' if str(values[0]) == '1' else 'ServiceGenerated'
            policy['CsrGeneration'] = {'Value': value, 'Locked': locked}
        if 'Certificate Authority' in self.attrs:
            values, locked = self.attrs['Certificate Authority']
            policy['CertificateAuthority'] = {'Value': values[0], 'Locked': locked}
        return policy

    def set_csr_state(self, state):
        self.attrs.pop(MANUAL_CSR, None)
        if TPP_STATES[state]:
            value, locked = TPP_STATES[state]
            self.attrs[MANUAL_CSR] = ([value], locked)

    def changed(self, local):
        return check_policy_specification(local, self.conn.get_policy(POLICY_DN), is_tpp=True)

    def apply(self, local):
        self.conn.set_policy(POLICY_DN, copy.deepcopy(local))


def tpp_local(policy_sg='omit', defaults_sg='omit'):
    """
    policy_sg set -> key algorithm/size locked in policy.keyPair (so the remote policy.keyPair exists).
    defaults_sg set -> key algorithm/size unlocked in defaults.keyPair (so the remote defaults.keyPair
    exists). Mirrors how a user would declare a locked vs. an unlocked CSR-generation setting.
    vcert's TPP set_policy requires exactly one country (and a state), hence the subject.
    """
    data = {'policy': {'domains': [], 'subject': {'countries': ['US'], 'states': ['Utah']}}}
    if defaults_sg == 'omit':
        kp = {'keyTypes': ['RSA'], 'rsaKeySizes': [2048]}
        if policy_sg != 'omit':
            kp['serviceGenerated'] = policy_sg
        data['policy']['keyPair'] = kp
    else:
        data['defaults'] = {'keyPair': {'keyType': 'RSA', 'rsaKeySize': 2048, 'ellipticCurve': None,
                                        'serviceGenerated': defaults_sg}}
    return parse_data(data)


def tpp_server(local, state):
    """A folder as a previous apply of `local` (serviceGenerated omitted) left it, plus a CSR state."""
    server = FakeTpp()
    seed = copy.deepcopy(local)
    seed.policy.key_pair.service_generated = None
    seed.defaults.key_pair.service_generated = None
    server.apply(seed)
    server.set_csr_state(state)
    return server


class TestTppServiceGenerated(unittest.TestCase):

    def test_policy_false_vs_unlocked_service_generated(self):
        # Local locks user-provided CSRs; the folder allows service generation by default (unlocked).
        # get_policy reports it only in defaults.keyPair, so a policy-only compare missed it.
        local = tpp_local(policy_sg=False)
        server = tpp_server(local, 'service-unlocked')
        is_changed, msgs = server.changed(local)
        self.assertTrue(is_changed)
        self.assertEqual(msgs, ['policy.keyPair.serviceGenerated changed. Local: False Remote: True'])
        server.apply(local)
        self.assertEqual(server.attrs[MANUAL_CSR], ([1], True))
        self.assertEqual(server.changed(local), (False, []), 'must converge after one apply')

    def test_defaults_false_vs_locked_service_generated(self):
        # Local defaults to user-provided CSRs; the folder LOCKS service generation. get_policy reports
        # it only in policy.keyPair, so a defaults-only compare missed it.
        local = tpp_local(defaults_sg=False)
        server = tpp_server(local, 'service-locked')
        is_changed, msgs = server.changed(local)
        self.assertTrue(is_changed)
        self.assertEqual(msgs, ['defaults.keyPair.serviceGenerated changed. Local: False Remote: True'])
        server.apply(local)
        self.assertEqual(server.attrs[MANUAL_CSR], ([1], False))
        self.assertEqual(server.changed(local), (False, []), 'must converge after one apply')

    def test_round_trip_matrix(self):
        # expected 'changed' before apply, per local declaration x remote CsrGeneration state
        expected = {
            ('policy', False): {'user-locked': False, 'service-locked': True, 'service-unlocked': True,
                                'user-unlocked': False, 'absent': False},
            ('policy', True): {'user-locked': True, 'service-locked': False, 'service-unlocked': True,
                               'user-unlocked': True, 'absent': True},
            ('policy', 'omit'): dict((s, False) for s in TPP_STATES),
            ('defaults', False): {'user-locked': False, 'service-locked': True, 'service-unlocked': True,
                                  'user-unlocked': False, 'absent': False},
            ('defaults', True): {'user-locked': True, 'service-locked': True, 'service-unlocked': False,
                                 'user-unlocked': True, 'absent': True},
        }
        failures = []
        for (block, sg), by_state in expected.items():
            local = tpp_local(policy_sg=sg) if block == 'policy' else tpp_local(defaults_sg=sg)
            for state, want in by_state.items():
                server = tpp_server(local, state)
                cell = '%s.serviceGenerated=%s remote=%s' % (block, sg, state)
                before = server.changed(local)
                if before[0] != want:
                    failures.append('%s before: expected changed=%s got %s' % (cell, want, before))
                server.apply(local)
                after = server.changed(local)
                if after[0]:
                    failures.append('%s after apply: perpetual drift %s' % (cell, after[1]))
        self.assertEqual(failures, [])
