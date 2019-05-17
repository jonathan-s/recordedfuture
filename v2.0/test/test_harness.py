import unittest
import os
import json
import requests

class RfTests(unittest.TestCase):
    """Test cases for all reputation actions."""

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

    def setUp(self, playbook):
        """Setup test environment."""
        self.phantom_host = os.environ['PHOST']
        self.phantom_cred = os.environ['PTOK']

        # Ensure the test_ip_reputation playbook is installed
        res = self._rest_get('playbook')
        self.pbid, self.pbactive = [(pbook['id'], pbook['active'])
                                    for pbook in res
                                    if pbook['name'] == playbook][0]

        self.assertTrue(self.pbactive, 'The Playbook %s is not active. '
                                       'Activate the Playbook.' % playbook)

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
        for page in range(2, jres['num_pages']):
            res = self._rest_call('get', path_info, payload={'page': page})
            result.extend(res.json()['data'])
        return result

    def assertCorrectRiskScore(self, result, target_risk_score, *args):
        try:
            risk_score = result['data'][0]['result_data'][0]['data'][0][
                'risk']['score']
        except Exception as err:
            print 'result: %s' % result
            raise
        self.assertEqual(risk_score, target_risk_score, *args)
