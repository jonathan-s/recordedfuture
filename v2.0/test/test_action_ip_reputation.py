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
    """Test cases for domain reputation action."""

    def setUp(self):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_ip_reputation_score(self, ioc, target_risk_score):
        """Test behavior when an ip is supplied."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact('IP Reputation',
                                                       destinationAddress=ioc)

        # Fetch the result of the automatic run.
        ares = self._action_result(container_id)

        # Check correct risk score.
        self.assertCorrectRiskScore(ares, target_risk_score,
                                    'result: %s' % ares)

    def test_ip_reputation(self):
        """Test behavior when an ip is supplied."""
        for ioc, target_risk_score in [('88.215.2.29', 99)]:
            self._test_ip_reputation_score(ioc, target_risk_score)
