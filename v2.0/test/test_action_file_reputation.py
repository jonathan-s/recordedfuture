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

        # Get 1 IP TARGETS with riskScore less than 89 and greater than 91.
        TARGETS = self.getTestDataByIocTypeAndRiskScore("Hash", 40, 90, 1)

        self.assertEquals(len(TARGETS), 1)

        for ioc, target_risk_score in TARGETS:
            self._test_file_reputation_score(ioc, target_risk_score)
