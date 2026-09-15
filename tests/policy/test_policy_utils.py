"""
Offline unit tests for policy_utils.check_policy_specification and helpers.

These construct real vcert PolicySpecification objects (no network) and lock in the venafi_policy
idempotency fix: identical specs must report unchanged, genuine drift must be detected, the three
former crash paths (empty default subject on one side, both default subjects populated, default
key_type None) must not raise, elliptic-curve / CA comparisons must be case-insensitive /
default-aware, and a minimal/declarative local file (omitting fields or whole blocks) must be
idempotent against a fully-populated remote. Live-verified against real NGTS CITs separately.
"""
import unittest

from vcert.policy import (PolicySpecification, Policy, Subject, KeyPair, SubjectAltNames,
                          Defaults, DefaultSubject, DefaultKeyPair)
from vcert.policy.policy_spec import DEFAULT_CA

from plugins.module_utils.policy_utils import (
    check_policy_specification, _check_list, _check_list_case_insensitive)


def full_ps():
    """A fully-populated PolicySpecification (every sub-object non-empty so all branches run)."""
    return PolicySpecification(
        owners=['alice'], users=['bob'], approvers=['carol'], user_access='rw',
        policy=Policy(
            domains=['vfidev.com'], wildcard_allowed=True, max_valid_days=90,
            cert_auth='DIGICERT\\DigiCert\\private_ssl_plus', auto_installed=False,
            subject=Subject(orgs=['Venafi'], org_units=['IT'], localities=['SLC'],
                            states=['Utah'], countries=['US']),
            key_pair=KeyPair(key_types=['RSA', 'EC'], rsa_key_sizes=[2048, 4096],
                             elliptic_curves=['P256', 'P384'], service_generated=True,
                             reuse_allowed=False),
            subject_alt_names=SubjectAltNames(dns_allowed=True, email_allowed=False, ip_allowed=False,
                                              upn_allowed=False, uri_allowed=False),
        ),
        defaults=Defaults(
            d_domain='vfidev.com',
            d_subject=DefaultSubject(org='Venafi', org_units=['IT'], locality='SLC',
                                     state='Utah', country='US'),
            d_key_pair=DefaultKeyPair(key_type='RSA', rsa_key_size=2048, elliptic_curve='P256',
                                      service_generated=True),
            auto_installed=False,
        ),
    )


def changed(local, remote, ignore_owners_users=False):
    is_changed, msgs = check_policy_specification(local, remote, ignore_owners_users=ignore_owners_users)
    return is_changed


class TestHelpers(unittest.TestCase):
    def test_check_list_multiset(self):
        self.assertTrue(_check_list([1, 2], [2, 1]))       # order-independent
        self.assertTrue(_check_list([1, 2], [1, 2]))
        self.assertFalse(_check_list([1, 1], [1, 2]))      # multiset: the old code wrongly said equal
        self.assertTrue(_check_list(None, []))
        self.assertFalse(_check_list([1], [1, 2]))

    def test_check_list_case_insensitive(self):
        self.assertTrue(_check_list_case_insensitive(['P256'], ['p256']))
        self.assertTrue(_check_list_case_insensitive(['P256', 'P384'], ['p384', 'p256']))
        self.assertFalse(_check_list_case_insensitive(['P256'], ['p384']))
        self.assertTrue(_check_list_case_insensitive(None, []))


class TestIdentityAndDrift(unittest.TestCase):
    def test_identical_is_unchanged(self):
        # Also guards the :206 org_units 3-tuple path (both default subjects populated).
        self.assertFalse(changed(full_ps(), full_ps()))

    def test_domains_diff(self):
        loc = full_ps()
        loc.policy.domains = ['other.com']
        self.assertTrue(changed(loc, full_ps()))

    def test_max_valid_days_diff(self):
        loc = full_ps()
        loc.policy.max_valid_days = 30
        self.assertTrue(changed(loc, full_ps()))

    def test_key_types_diff(self):
        loc = full_ps()
        loc.policy.key_pair.key_types = ['RSA']
        self.assertTrue(changed(loc, full_ps()))

    def test_rsa_sizes_diff(self):
        loc = full_ps()
        loc.policy.key_pair.rsa_key_sizes = [2048]
        self.assertTrue(changed(loc, full_ps()))

    def test_subject_orgs_diff(self):
        loc = full_ps()
        loc.policy.subject.orgs = ['Other']
        self.assertTrue(changed(loc, full_ps()))


class TestCurveCasing(unittest.TestCase):
    def test_lowercase_curves_match(self):
        loc = full_ps()
        loc.policy.key_pair.elliptic_curves = ['p256', 'p384']
        self.assertFalse(changed(loc, full_ps()))

    def test_genuine_curve_diff(self):
        loc = full_ps()
        loc.policy.key_pair.elliptic_curves = ['p256']
        self.assertTrue(changed(loc, full_ps()))

    def test_default_curve_casing_match(self):
        loc = full_ps()
        loc.defaults.key_pair.elliptic_curve = 'p256'
        self.assertFalse(changed(loc, full_ps()))


class TestCertAuthorityLandmine(unittest.TestCase):
    def test_local_default_ca_is_ignored(self):
        # User omits CA -> the SDK forces DEFAULT_CA; must not report a false change vs a real remote CA.
        loc = full_ps()
        loc.policy.certificate_authority = DEFAULT_CA
        self.assertFalse(changed(loc, full_ps()))

    def test_genuine_ca_diff_detected(self):
        loc = full_ps()
        loc.policy.certificate_authority = 'MYCA\\Intermediate\\Template'
        rem = full_ps()
        rem.policy.certificate_authority = 'OTHER\\Intermediate\\Template'
        self.assertTrue(changed(loc, rem))


class TestFormerCrashPaths(unittest.TestCase):
    def test_default_key_type_none_no_crash(self):
        # :232 — reached when only rsa_key_size/elliptic_curve set; key_type None must not crash.
        loc = full_ps()
        loc.defaults.key_pair.key_type = None
        rem = full_ps()
        rem.defaults.key_pair.key_type = None
        self.assertFalse(changed(loc, rem))  # would AttributeError before the fix

    def test_remote_default_subject_empty_no_crash(self):
        # :200 — local default subject populated, remote empty. TypeError before the fix.
        rem = full_ps()
        rem.defaults.subject = DefaultSubject()  # all None -> empty
        self.assertTrue(changed(full_ps(), rem))

    def test_both_default_subjects_populated_orgunits_diff(self):
        # :206 — both default subjects populated; org_units 3-tuple. ValueError before the fix.
        loc = full_ps()
        loc.defaults.subject.org_units = ['IT']
        rem = full_ps()
        rem.defaults.subject.org_units = ['Eng']
        self.assertTrue(changed(loc, rem))


class TestNgtsIgnoreOwnersUsers(unittest.TestCase):
    def test_ngts_skips_owners_users(self):
        # NGTS remote always returns owners/users/approvers empty; a local file listing them must not
        # churn when ignore_owners_users=True, but must be flagged otherwise.
        loc = full_ps()
        rem = full_ps()
        rem.owners = []
        rem.users = []
        rem.approvers = []
        rem.user_access = 'rw'
        self.assertFalse(changed(loc, rem, ignore_owners_users=True))
        self.assertTrue(changed(loc, rem, ignore_owners_users=False))


class TestMinimalDeclarativeFiles(unittest.TestCase):
    """A minimal/declarative local file (omitting fields or whole blocks) must be idempotent against
    a fully-populated remote: an omitted value means 'unspecified', not 'set to empty'. Without this
    the module reported 'changed' on every run for realistic minimal policy files."""

    def test_minimal_only_declared_fields_unchanged(self):
        # Declares only domains + key_types (both matching remote); everything else omitted.
        loc = PolicySpecification(policy=Policy(
            domains=['vfidev.com'], key_pair=KeyPair(key_types=['RSA', 'EC'])))
        self.assertFalse(changed(loc, full_ps()))

    def test_minimal_still_detects_declared_drift(self):
        # A field the minimal file *does* declare must still be diffed (no over-skipping).
        loc = PolicySpecification(policy=Policy(
            domains=['other.com'], key_pair=KeyPair(key_types=['RSA', 'EC'])))
        self.assertTrue(changed(loc, full_ps()))

    def test_omitted_scalars_do_not_churn(self):
        # max_valid_days / wildcard_allowed omitted locally (None) must not report changed.
        loc = full_ps()
        loc.policy.max_valid_days = None
        loc.policy.wildcard_allowed = None
        self.assertFalse(changed(loc, full_ps()))

    def test_omitted_elliptic_curves_do_not_churn(self):
        # RSA+EC key types kept, ellipticCurves omitted -> unspecified -> no change.
        loc = full_ps()
        loc.policy.key_pair.elliptic_curves = None
        self.assertFalse(changed(loc, full_ps()))

    def test_omitted_rsa_sizes_do_not_churn(self):
        loc = full_ps()
        loc.policy.key_pair.rsa_key_sizes = None
        self.assertFalse(changed(loc, full_ps()))

    def test_omitted_subject_block_does_not_churn(self):
        loc = full_ps()
        loc.policy.subject = Subject()  # all-empty -> unspecified
        self.assertFalse(changed(loc, full_ps()))

    def test_omitted_defaults_block_does_not_churn(self):
        loc = full_ps()
        loc.defaults = Defaults()
        self.assertFalse(changed(loc, full_ps()))

    def test_local_declares_block_remote_lacks_is_changed(self):
        # Complementary direction: local declares a subject the remote lacks -> genuine change.
        rem = full_ps()
        rem.policy.subject = Subject()
        self.assertTrue(changed(full_ps(), rem))


class TestUriProtocolsIpConstraints(unittest.TestCase):
    """uri_protocols / ip_constraints were never diffed, so a protocol/constraint change with the
    *_allowed flag unchanged was silently missed. They are now compared when the local spec lists
    them (guarded so an omitted local list does not false-positive)."""

    @staticmethod
    def _ps(uri_protocols=None, ip_constraints=None):
        return PolicySpecification(policy=Policy(
            domains=['vfidev.com'],
            subject_alt_names=SubjectAltNames(
                dns_allowed=True, email_allowed=False, ip_allowed=True,
                upn_allowed=False, uri_allowed=True,
                uri_protocols=uri_protocols, ip_constraints=ip_constraints)))

    def test_uri_protocols_drift_detected(self):
        self.assertTrue(changed(self._ps(uri_protocols=['ldaps']), self._ps(uri_protocols=['https'])))

    def test_uri_protocols_match_case_insensitive(self):
        self.assertFalse(changed(self._ps(uri_protocols=['https']), self._ps(uri_protocols=['HTTPS'])))

    def test_uri_protocols_omitted_local_no_churn(self):
        # Local omits the list (remote returns it populated) -> unspecified -> no false 'changed'.
        self.assertFalse(changed(self._ps(uri_protocols=None), self._ps(uri_protocols=['https'])))

    def test_ip_constraints_drift_detected(self):
        self.assertTrue(changed(self._ps(ip_constraints=['v4']), self._ps(ip_constraints=['v4', 'v6'])))

    def test_ip_constraints_omitted_local_no_churn(self):
        self.assertFalse(changed(self._ps(ip_constraints=None), self._ps(ip_constraints=['v4'])))


if __name__ == "__main__":
    unittest.main()
