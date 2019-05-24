"""Test suite for domain intelligence action"""
import logging
import requests
from phantom_ops import *
from test_harness import RfTests

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_intelligence_test'


class RfDomainIntelligenceTests(RfTests):
    """Test cases for domain intelligence action."""

    def setUp(self):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_domain_intelligence_score(self, ioc, target_risk_score):
        """Test behavior when a domain is supplied."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            'Test Event Domain Intelligence',
            destinationDnsDomain=ioc)

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        # Check correct risk score.
        self.assertCorrectRiskScore(ares, target_risk_score,
                                    'result: %s' % ares)

        # Check that we have metrics data
        self.assertMetrics(ares)

    def test_domain_intelligence(self):
        """Test behavior when a domain is supplied."""
        targets = self.high_risk_iocs_by_category('domain', 5, fields=['entity',
                                                                       'risk'])

        # Call the test for each target
        for ioc, target_risk_score in targets:
            self._test_domain_intelligence_score(ioc, target_risk_score)
