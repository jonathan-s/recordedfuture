import unittest
import os
import json
import time
from time import sleep
import requests
from phantom_ops import *


class RfTests(unittest.TestCase):
    """Test cases for all reputation actions."""

    POLL_MAXTRIES = 10
    POLL_WAITTIME = 0.25

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

    def _create_event_and_artifact(self, category, **kwargs):
        """Create an event with an artifact.

        Returns the id of the created container."""
        artifact = ph_artifact(**kwargs)
        container = ph_container("%s event" % category, [artifact])
        res = self._rest_call('post', 'container', container)

        # Check that it was a success.
        self.assertEqual(res.status_code, 200)

        # Check the Phantom status
        time.sleep(1)  # XXX should try and poll for completion instead
        jres = res.json()
        self.assertEqual(jres['success'], True)

        return jres['id']

    def _action_result(self, container_id):
        """Return the result of an action."""
        print '_filter_container: %s' % container_id
        return self._rest_call('get', 'app_run',
                               {'_filter_container': container_id,
                                'include_expensive': True}).json()

    # Let's hold of on this for a bit, we need to figure out how to poll
    # without re-running the call
    #
    # def _poll_for_success(self, fn, params, maxtries=POLL_MAXTRIES, waittime=POLL_WAITTIME):
    #     """Polls the return from the passed function until successfull."""
    #     # The action is not triggered immediately, returning an empty data array.
    #     # So we check count before checking the status of the action
    #     tries = 0
    #     while True:
    #         tries = tries + 1
    #         if (tries > maxtries):
    #             raise Exception('Max tries %s exceeded when polling for request success' % maxtries)
    #
    #         # Call passed in function with passed params
    #         res = fn(params)
    #         if res['count'] > 0:
    #             if res['data'][0]['status'] == 'success':
    #                 break
    #         sleep(waittime)
    #
    #     return res

    def _poll_for_success(self, fn, params):
        sleep(2)
        return fn(params)

    def assertCorrectRiskScore(self, result, target_risk_score, *args):
        try:
            risk_score = result['data'][0]['result_data'][0]['data'][0][
                'risk']['score']
        except Exception as err:
            print ('result: %s' % result)
            raise
        self.assertEqual(risk_score, target_risk_score, *args)
