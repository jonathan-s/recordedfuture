"""Test suite for ip reputation action"""
import logging
import requests
from phantom_ops import *
from test_harness import RfTests

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_alert_test'


class RfAlertDataLookupTests(RfTests):
    """Test cases for ip reputation action."""

    def setUp(self):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def test_alert_data_lookup(self):
        """Test behavior when an ip is supplied."""
        artifact = ph_artifact(cs1="VNPVFc",
                               cs1Label="alert rule id",
                               cs2="anytime")
        container = ph_container("Alert Data event", [artifact])
        res = self._rest_call('post', 'container', container)

        # Check that it was a success.
        self.assertEqual(res.status_code, 200)

        # Check the Phantom status
        jres = res.json()
        self.assertEqual(jres['success'], True)

        artifact_id = jres['id']