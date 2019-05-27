"""Test suite for ip intelligence action"""
import logging
import requests
from test_harness import RfTests

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_intelligence_test'


class RfIpReputationTests(RfTests):
    """Test cases for ip intelligence action."""

    def setUp(self):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_ip_intelligence_data(self, ioc, target_risk_score, cname):
        """Test behavior when an ip is supplied."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            cname,
            destinationAddress=ioc)

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        # Check correct risk score.
        self.assertCorrectRiskScore(ares, target_risk_score,
                                    'result: %s' % ares)

        # Check that we have metrics data
        self.assertMetrics(ares)

    def test_ip_intelligence(self):
        """Test behavior when an ip is supplied."""
        targets = self.high_risk_iocs_by_category('ip', 5, fields=['entity',
                                                                   'risk'])

        # Call the test for each target
        for ioc, target_risk_score in targets:
            self._test_ip_intelligence_data(ioc, target_risk_score,
                                            'Test Event IP Intelligence')

    def test_neg_ip_intelligence(self):
        """Test behavior when an ip without info is supplied."""
        targets = [('1.2.3.4', 0)]

        # Call the test for each target
        for ioc, target_risk_score in targets:
            self._test_ip_intelligence_data(
                ioc, target_risk_score,
                'Test Event Neg IP Intelligence (no info IOC)')
