"""Test suite for ip reputation action"""
import logging
import requests
from phantom_ops import *
from test_harness import RfTests
import time

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_reputation_test'


class RfIpReputationTests(RfTests):
    """Test cases for ip reputation action."""

    def setUp(self, **kwargs):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_ip_reputation_score(self, ioc, target_risk_score):
        """Given an IOC (entity), verify that the risk score is correct."""
        artifact = ph_artifact(destinationAddress=ioc)
        container = ph_container("IP Reputation event", [artifact])
        res = self._rest_call('post', 'container', container)

        # Check that it was a success.
        self.assertEqual(res.status_code, 200)

        # Check the Phantom status
        time.sleep(1)  # XXX should try and poll for completion instead
        jres = res.json()
        self.assertEqual(jres['success'], True)

        container_id = jres['id']
        ares = self._rest_call(
            'get', 'app_run',
            {'_filter_container': container_id,
             'include_expensive': True}).json()
        self.assertCorrectRiskScore(ares, target_risk_score,
                                    'result: %s' % ares)

    def test_ip_reputation(self):
        """Test behavior when an ip is supplied."""
        for ioc, target_risk_score in [('194.36.189.177', 99)]:
            self._test_ip_reputation_score(ioc, target_risk_score)
