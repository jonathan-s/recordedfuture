"""Test suite for url reputation action"""
import logging
import requests
from phantom_ops import *
from test_harness import RfTests

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_url_reputation_test'


class RfUrlReputationTests(RfTests):
    """Test cases for url reputation action."""

    def setUp(self):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def test_domain_reputation(self):
        """Test behavior when a domain is supplied."""
        artifact = ph_artifact(requestURL="https://www.google.com")
        container = ph_container([artifact])
        res = self._rest_call('post', 'container', container)

        # Check that it was a success.
        self.assertEqual(res.status_code, 200)

        # Check the Phantom status
        jres = res.json()
        self.assertEqual(jres['success'], True)

        artifact_id = jres['id']