"""Test suite for domain reputation action"""
import logging
import requests
from test_harness import RfTests

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_reputation_test'


class RfIpReputationTests(RfTests):
    """Test cases for ip reputation action."""

    def setUp(self):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_ip_reputation_score(self, ioc, target_risk_score):
        """Test behavior when an ip is supplied."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            'Test Event IP Reputation', destinationAddress=ioc)

        # Fetch the result of the automatic run.
        ares = self._action_result(container_id)

        # Check correct risk score.
        self.assertCorrectRiskScore(ares, target_risk_score,
                                    'result: %s' % ares)

    def test_ip_reputation(self):
        """Test behavior when a single ip is supplied."""
        targets = self.high_risk_iocs_by_category('ip', 5, fields=['entity',
                                                                   'risk'])

        self.assertEquals(len(TARGETS), 1)

        # Call the test for each target
        for ioc, target_risk_score in targets:
            self._test_ip_reputation_score(ioc, target_risk_score)
