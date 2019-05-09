"""Test suite for rf_alerts.py"""
import unittest
import os
import logging
import json
import requests
from phantom_ops import *

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)


class RfIpReputationTests(unittest.TestCase):
    """Test cases for ip reputation action."""

    @classmethod
    def setUpClass(cls):
        """Verify pre-conditions."""
        if 'PHOST' not in os.environ:
            raise Exception('This test script must be called with the '
                            'environment variable PHOST set. This variable '
                            'must contain the name of a development '
                            'phantom server (ex phantom-dev-xx-01).')
        if 'PTOK' not in os.environ:
            raise Exception('This test script must be called with the '
                            'environment variable PTOK set. This variable '
                            'must contain an automation token.')

    def setUp(self):
        """Setup test environment."""
        self.phantom_host = os.environ['PHOST']
        self.phantom_cred = os.environ['PTOK']

        # Ensure the test_ip_reputation playbook is installed
        res = self._rest_get('playbook')
        self.pbid = [pbook['id'] for pbook in res
                     if pbook['name'] == 'recorded_future_IP_reputation_test'][0]

    def _rest_call(self, method, path_info, payload=None):
        """Abstract REST call."""
        if method == 'post':
            return requests.post('https://%s/rest/%s' % (self.phantom_host,
                                                         path_info),
                                 headers={'ph-auth-token': self.phantom_cred},
                                 data=json.dumps(payload),
                                 verify=False)
        elif method == 'get':
            return requests.get('https://%s/rest/%s' % (self.phantom_host,
                                                        path_info),
                                params=payload,
                                headers={'ph-auth-token': self.phantom_cred},
                                verify=False)

    def _rest_get(self, path_info, payload=None):
        """Make a REST get call, merge if multiple pages in response."""
        res = self._rest_call('get', path_info, payload)
        jres = res.json()
        result = jres['data']
        for page in range(2,jres['num_pages']):
            res = self._rest_call('get', path_info, payload={'page': page})
            result.extend(res.json()['data'])
        return result

    def test_ip_reputation(self):
        """Test behavior when an ip is supplied."""
        artifact = ph_artifact(destinationAddress="129.16.1.4")
        container = ph_container([artifact])
        res = self._rest_call('post', 'container', container)

        # Check that it was a success.
        self.assertEqual(res.status_code, 200)

        # Check the Phantom status
        jres = res.json()
        self.assertEqual(jres['success'], True)

        artifact_id = jres['id']
