"""Test suite for domain reputation action"""
import logging
import requests
from phantom_ops import *
from test_harness import RfTests

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_reputation_test'


class RfDomainReputationTests(RfTests):
    """Test cases for domain reputation action."""

    def setUp(self):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_domain_reputation_score(self, ioc, target_risk_score):
        """Test behavior when a domain is supplied."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact('Domain Reputation',
                                                       destinationDnsDomain=ioc)

        # Fetch the result of the automatic run.
        ares = self._action_result(container_id)

        # Check correct risk score.
        self.assertCorrectRiskScore(ares, target_risk_score,
                                    'result: %s' % ares)

    def test_domain_reputation(self):
        """Test behavior when a domain is supplied."""
        for ioc, target_risk_score in [('ddobnajanu.club', 96)]:
            self._test_domain_reputation_score(ioc, target_risk_score)
