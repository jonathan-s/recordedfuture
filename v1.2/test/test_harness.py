import unittest
import os
import json
import time
from time import sleep
import requests
from phantom_ops import *
import logging
from jsonpath_rw import jsonpath, parse
from rfapi import RawApiClient, ConnectApiClient

LGR = logging.getLogger(__name__)


class RfTests(unittest.TestCase):
    """Test cases for all reputation actions."""

    POLL_MAXTRIES = 20
    POLL_WAITTIME = 1

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
        self.phantom_playbook = playbook

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
        container = ph_container("%s event" % category, [artifact],
                                 self.phantom_playbook)
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
        LGR.debug('_filter_container: %s', container_id)
        return self._rest_call('get', 'app_run',
                               {'_filter_container': container_id,
                                'include_expensive': True}).json()

    def _poll_for_success(self, fn, params, maxtries=POLL_MAXTRIES,
                          waittime=POLL_WAITTIME):
        """Polls until no action_results are in running mode.

        The action is not triggered immediately, returning an empty data array.
        So we check count before checking the status of the action
        """
        for attempt in range(maxtries):
            # Call passed in function with passed params
            res = fn(params)
            try:
                assert (len(res['data']) > 0)  # wait for any results
                LGR.info('len: %s', len(res['data']))

                # Check overall status
                jpath = parse('$.data[*].status')
                running = [match.value for match in jpath.find(res)
                           if match.value == 'running']
                LGR.info('running: %s', running)
                assert (running == [])  # wait until no more running

                # Check status for each parameter set
                jpath = parse('$.data[*].result_data[*].status')
                running2 = [match.value for match in jpath.find(res)
                            if match.value == 'running']
                LGR.info('running2: %s', running)
                assert (running2 == [])  # wait until no more running

                # Nothing is left in running state, we're ready to evaluate
                return res
            except AssertionError:
                pass

            sleep(waittime)

        raise Exception(
            'Max tries %s exceeded when polling for request success' % maxtries)

    def assertCorrectRiskScore(self, result, target_risk_score, *args):
        """Assert that the risk score matches the target."""
        try:
            risk_score = result['data'][0]['result_data'][0]['data'][0][
                'risk']['score']
        except Exception as err:
            LGR.error('result %s', result['data'])
            raise
        self.assertEqual(risk_score, target_risk_score, *args)

    def assertMetrics(self, result):
        """Assert that metrics for totalHits exists and is an int."""
        metrics = result['data'][0]['result_data'][0]['data'][0]['metrics']
        total_hits = [met['value'] for met in metrics
                      if met['type'] == 'totalHits'][0]
        self.assertIsInstance(total_hits, int)

    def high_risk_iocs_by_category(self, category, limit, **kwargs):
        """Return limit IOCs of a category."""
        api = ConnectApiClient()
        res = api.search(category, limit=limit, **kwargs)
        return [(entity['entity']['name'], entity['risk']['score'])
                for entity in res.entities]

    # def get_test_data_by_ioc_type_and_risk_score(self, type, rs_min, rs_max,
    #                                              limit):
    #     """Function that queries RawAPI for IOCs for a specific data group
    #     and risk score .
    #     """
    #     api = RawApiClient()
    #
    #     query = {
    #         "cluster": {
    #             "data_group": type,
    #             "limit": limit,
    #             "attributes": [
    #                 {
    #                     "name": "stats.metrics.riskScore",
    #                     "range": {
    #                         "gt": rs_min
    #                     }
    #                 },
    #                 {
    #                     "name": "stats.metrics.riskScore",
    #                     "range": {
    #                         "lt": rs_max
    #                     }
    #                 }
    #             ]
    #         },
    #         "output": {
    #             "exclude": [
    #                 "stats.entity_lists"
    #             ],
    #             "inline_entities": True
    #         }
    #     }
    #
    #     res = api.query(query)
    #
    #     self.assertEquals(res.result['status'], 'SUCCESS');
    #
    #     targets = []
    #     for event in res.result['events']:
    #         ip = event['attributes']['entities'][0]['name']
    #         riskScore = event['stats']['metrics']['riskScore']
    #         targets.append((ip, riskScore))
    #
    #     return targets
