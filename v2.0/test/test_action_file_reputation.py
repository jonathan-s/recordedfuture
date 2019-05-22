"""Test suite for file reputation action"""
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
    """Test cases for file reputation action."""

    def setUp(self):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_file_reputation_score(self, ioc, target_risk_score):
        """Test behavior when a file is supplied."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact('File Reputation',
                                                       fileHash=ioc)

        # Fetch the result of the automatic run.
        ares = self._action_result(container_id)

        # Check correct risk score.
        self.assertCorrectRiskScore(ares, target_risk_score,
                                    'result: %s' % ares)

    def test_file_reputation(self):
        """Test behavior when a file is supplied."""
        for ioc, target_risk_score in [
            ('e285b6ce047015943e685e6638bd837e', 89)]:
            self._test_file_reputation_score(ioc, target_risk_score)
