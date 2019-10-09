"""Test suite for url reputation action"""
import logging
import requests
from test_harness import RfTests
import testdata.common.not_found as nf

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
        self.assertCorrectRiskScore(ares, target_risk_score)

    def test_url_reputation(self):
        """Test behavior when a url is supplied."""
        # targets = self.high_risk_iocs_by_category('url', 5, fields=['entity',
        #                                                             'risk'])

        targets = [
            ("http://down7047.yyk2.com/?/74394/pc6/%CE%BE%CF%B7%D5%BD%C6%BD%CC%A8.exe", 5),
            ("http://cdd.net.ua/apothecary/shopping_cart.php?osCsid=4e24988fb404907b731701c72e82f13b", 5),
            ("https://themwebis.com/images/docusign17/index.php", 5),
            ("http://down.zmnds.com/cx/180806/4/cad2007%E6%B3%A8@19_432704WrsQS.exe", 5),
            ("http://bd10.52lishi.com/bd70818.zip", 65)]

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
        response, message = nf.testdata_reputation_na(
            testdata['ioc'], 'url')
        result_data = ares['data'][0]['result_data']
        for rd in result_data:
            # Assert success
            self.assertEqual(rd['status'], 'success')
            # Assert message is as should
            self.assertEqual(rd['message'], message)
            # Assert data
            self.assertEqual(rd['data'], response)
