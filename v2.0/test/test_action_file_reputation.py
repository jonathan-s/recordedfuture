"""Test suite for file reputation action"""
import logging
import requests
from test_harness import RfTests
import testdata.common.not_found as nf

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_reputation_test'


class RfDomainReputationTests(RfTests):
    """Test cases for file reputation action."""

    def setUp(self, playbook=None):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_file_reputation_score(self, ioc, target_risk_score):
        """Test behavior when a file is supplied."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            'Test Event file reputation',
            fileHash=ioc)

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        # Check correct risk score.
        self.assertCorrectRiskScore(ares, target_risk_score)

    def test_file_reputation(self):
        """Test behavior when a file is supplied."""
        # targets = self.high_risk_iocs_by_category('hash', 5, fields=['entity',
        #                                                              'risk'])
        targets = [
            ("73017643a89cc5c961494b84feb60751", 70),
            ("31617dce34ae7dcba3296f2be55d91756f1f878a0b1878304c8adda8b28e0a90", 70),
            ("bb85b1c9f2006db588690e6c38802f97", 70),
            ("667a56c7014dce3351f63a9b1c1957e6a29977b8736fa5a6f0e0192ac6c147d7", 65),
            ("057942b64c3f3fe5eb8f1856f0c860f9036f9c87", 25)]

        # Call the test for each target
        for ioc, target_risk_score in targets:
            self._test_file_reputation_score(ioc, target_risk_score)

    def test_neg_file_reputation_not_existing(self):
        """Test behavior when a non-existing file is supplied."""

        testdata = {
            # v2.0> md5 Makefile
            'ioc': 'a776826e08aba01a134d78701cf0969a'
        }

        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            'Test Event file reputation - not existing',
            fileHash=testdata['ioc'])

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        LOGGER.debug("ares: %s", ares)

        # ConnectAPI return 404 on these, but we return success with an empty list
        self.assertEqual(ares['data'][0]['status'], 'success')

        # Assert we get success and sets the response as expected
        response, message = nf.testdata_reputation_na(
            testdata['ioc'], 'hash')
        result_data = ares['data'][0]['result_data']
        for rd in result_data:
            # Assert success
            self.assertEqual(rd['status'], 'success')
            # Assert message is as should
            self.assertEqual(rd['message'], message)
            # Assert data
            self.assertEqual(rd['data'], response)
