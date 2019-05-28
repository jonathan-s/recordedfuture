"""Test suite for ip intelligence action"""
import logging
import requests
from test_harness import RfTests
import unittest
from testdata.common.not_found import testdata_404_intelligence_ip

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
        testdata = {
            'ioc': '1.2.3.4'
        }

        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            'Test Event IP Intelligence - not existing', destinationAddress=testdata['ioc'])

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        LOGGER.debug("ares: %s", ares)

        # ConnectAPI return 404 on these, but we return success with an empty list
        self.assertEqual(ares['data'][0]['status'], 'success')

        # Assert we get success and sets the response as expected
        result_data = ares['data'][0]['result_data']
        for rd in result_data:
            # Assert success
            self.assertEqual(rd['status'], 'success')
            # Assert message is as should
            self.assertEqual(rd['message'], testdata_404_intelligence_ip['message'])
            # Assert data property
            self.assertEqual(rd['data'], testdata_404_intelligence_ip['data'])
