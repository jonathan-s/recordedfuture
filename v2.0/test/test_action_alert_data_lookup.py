"""Test suite for ip reputation action"""
import logging
import requests
from phantom_ops import *
from test_harness import RfTests
import unittest

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

    def test_ok_alert_data_lookup(self):
        """Test behavior when passing alert query parameters returning data."""

        testdata = {
            'alertruleid':          'VNPVFc',
            'alertrulelabel':       'alert rule id',
            'alertruletimeframe':   'anytime',
            'alertrulename':        'recordedfuture.com Leaked Credentials Document'
        }

        artifact = ph_artifact(cs1=testdata['alertruleid'],
                               cs1Label=testdata['alertrulelabel'],
                               cs2=testdata['alertruletimeframe'])

        container = ph_container("Alert Data event", [artifact])

        res = self._rest_call('post', 'container', container)

        # Check that it was a success.
        self.assertEqual(res.status_code, 200)

        # Check the Phantom status
        jres = res.json()
        self.assertEqual(jres['success'], True)

        # Pass self._action_result to poll with container id as argument
        ares = self._poll_for_success(self._action_result, [jres['id']])

        # Assert that the call to RF was success
        self.assertEqual(ares['data'][0]['result_data'][0]['status'], 'success')

        # Assert summary has required fields of correct type
        self.assertIsInstance(ares['data'][0]['result_data'][0]['summary']['returned_number_of_alerts'], int)
        self.assertIsInstance(ares['data'][0]['result_data'][0]['summary']['total_number_of_alerts'], int)
        self.assertIsInstance(ares['data'][0]['result_data'][0]['summary']['rule_name'], str)
        self.assertIsInstance(ares['data'][0]['result_data'][0]['summary']['rule_id'], str)

        # Assert rule values in summary
        self.assertEquals(ares['data'][0]['result_data'][0]['summary']['rule_id'], testdata['alertruleid'])
        self.assertEquals(ares['data'][0]['result_data'][0]['summary']['rule_name'], testdata['alertrulename'])

        # Assert data properties if data is returned
        if len(ares['data'][0]['result_data'][0]['data']) > 0:
            # Assert alerts
            self.assertIsInstance(ares['data'][0]['result_data'][0]['data'][0]['alerts'], list)

            alert = ares['data'][0]['result_data'][0]['data'][0]['alerts'][0]['alert']
            self.assertIsInstance(alert['content'], dict)
            self.assertIsInstance(alert['entities'], dict)
            self.assertIsInstance(alert['alertTitle'], str)
            self.assertIsInstance(alert['alertUrl'], str)
            self.assertIsInstance(alert['triggered'], str)

            # Assert rule
            self.assertIsInstance(ares['data'][0]['result_data'][0]['data'][0]['rule'], dict)

            rule = ares['data'][0]['result_data'][0]['data'][0]['rule']
            self.assertEquals(rule['id'], testdata['alertruleid'])
            self.assertEquals(rule['name'], testdata['alertrulename'])


    def test_neg_alert_data_lookup_no_match(self):
        """Test behavior when passing alert query parameters that do not return data."""

        testdata = {
            'alertruleid':          'KALLE',
            'alertrulelabel':       'neg alert rule id',
            'alertruletimeframe':   'anytime'
        }

        artifact = ph_artifact(cs1=testdata['alertruleid'],
                               cs1Label=testdata['alertrulelabel'],
                               cs2=testdata['alertruletimeframe'])

        container = ph_container("Neg Alert Data event", [artifact])

        res = self._rest_call('post', 'container', container)

        # Check that it was a success.
        self.assertEqual(res.status_code, 200)

        # Check the Phantom status
        jres = res.json()
        self.assertEqual(jres['success'], True)

        # Get action result
        ares = self._action_result([jres['id']])

        # Assert we get empty values
        self.assertEqual(ares['count'], 0)
        self.assertEqual(ares['num_pages'], 0)
        self.assertEqual(len(ares['data']), 0)

    @unittest.skip("Skipping due to https://recordedfuture.atlassian.net/browse/RF-41776")
    def test_neg_alert_data_lookup_invalid_timeframe(self):
        """Test behavior when passing alert query parameters with invalid timeframe."""

        testdata = {
            'alertruleid':          'VNPVFc',
            'alertrulelabel':       'neg alert rule timestamp invalid',
            'alertruletimeframe':   'kalle'
        }

        artifact = ph_artifact(cs1=testdata['alertruleid'],
                               cs1Label=testdata['alertrulelabel'],
                               cs2=testdata['alertruletimeframe'])

        container = ph_container("Neg Alert Data event", [artifact])

        res = self._rest_call('post', 'container', container)

        # Check that it was a success.
        self.assertEqual(res.status_code, 200)

        # # Check the Phantom status

        # jres = res.json()
        # self.assertEqual(jres['success'], True)

        # Here we get a
        # # Get action result
        # ares = self._action_result([jres['id']])
        #
        # print(ares)
        #
        # # Assert we get empty values
        # self.assertEqual(ares['count'], 0)
        # self.assertEqual(ares['num_pages'], 0)
        # self.assertEqual(len(ares['data']), 0)
