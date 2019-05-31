"""Test suite for url reputation action"""
import logging
import requests
from test_harness import RfTests
from testdata.common.not_found import testdata_404_reputation

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_reputation_test'


class RfUrlReputationTests(RfTests):
    """Test cases for url reputation action."""

    def setUp(self, playbook=None):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_url_reputation_score(self, ioc, target_risk_score):
        """Test behavior when a url is supplied."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            'Test Event Url Reputation',
            requestURL=ioc)

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        # Check correct risk score.
        self.assertCorrectRiskScore(ares, target_risk_score,
                                    'result: %s' % ares)

    def test_url_reputation(self):
        """Test behavior when a url is supplied."""
        targets = self.high_risk_iocs_by_category('url', 5, fields=['entity',
                                                                    'risk'])

        # Call the test for each target
        for ioc, target_risk_score in targets:
            self._test_url_reputation_score(ioc, target_risk_score)

    def test_neg_url_reputation_not_existing(self):
        """Test behavior when a non-existing url is supplied."""

        testdata = {
            'ioc': 'https://min.pretty.obefinliga.url/nonexistingurl'
        }

        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            'Test Event Url Reputation - not existing',
            requestURL=testdata['ioc'])

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        LOGGER.debug("ares: %s", ares)

        # ConnectAPI return 404 on these, but we return success with an
        # empty list
        self.assertEqual(ares['data'][0]['status'], 'success')

        # Assert we get success and sets the response as expected
        result_data = ares['data'][0]['result_data']
        for rd in result_data:
            # Assert success
            self.assertEqual(rd['status'], 'success')
            # Assert message is as should
            self.assertEqual(rd['message'],
                             testdata_404_reputation['message'])
            # Assert data
            self.assertEqual(rd['data'], testdata_404_reputation['data'])
