"""Test suite for domain reputation action"""
import logging
import requests
from test_harness import RfTests
import testdata.common.not_found as nf

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_reputation_test'


class RfIpReputationTests(RfTests):
    """Test cases for ip reputation action."""

    def setUp(self, playbook=None):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_ip_reputation_score(self, ioc, target_risk_score, cname):
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

    def test_ip_reputation(self):
        """Test behavior when a single ip is supplied."""
        # targets = self.high_risk_iocs_by_category('ip', 5, fields=['entity',
        #                                                           'risk'])
        targets = [
            ("184.53.48.252", 5),
            ("14.177.126.193", 23),
            ("105.156.186.187", 18),
            ("160.177.196.170", 18),
            ("2.141.179.222", 18)]

        # Call the test for each target
        for ioc, target_risk_score in targets:
            self._test_ip_reputation_score(ioc, target_risk_score,
                                           'Test Event IP Reputation')

    def test_neg_ip_reputation_not_existing(self):
        """Test behavior when a non-existing ip is passed."""
        testdata = {
            'ioc': '129.16.1.4'
        }

        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            'Test Event IP Reputation - not existing',
            destinationAddress=testdata['ioc'])

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        LOGGER.debug("ares: %s", ares)

        # ConnectAPI return 404 on these, but we return success with an
        # empty list
        self.assertEqual(ares['data'][0]['status'], 'success')

        # Assert we get success and sets the response as expected
        response, message = nf.testdata_reputation_wo_risk(
            testdata['ioc'], 'ip')
        result_data = ares['data'][0]['result_data']
        for rd in result_data:
            # Assert success
            self.assertEqual(rd['status'], 'success')
            # Assert message is as should
            self.assertEqual(rd['message'], message)
            # Assert data
            self.assertEqual(rd['data'], response)
