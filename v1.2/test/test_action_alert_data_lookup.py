"""Test suite for ip reputation action"""
import logging
import requests
import re
from test_harness import RfTests

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_alert_test'


class RfAlertDataLookupTests(RfTests):
    """Test cases for ip reputation action."""

    def setUp(self, playbook=None):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def test_ok_single_alert_data_lookup(self):
        """Test behavior when passing alert query parameters returning data."""

        testdata = {
            'alertruleid': 'VNPVFc',
            'alertrulelabel': 'alert rule id',
            'alertruletimeframe': 'anytime',
            'alertrulename': 'recordedfuture.com Leaked Credentials Document'
        }

        container_id = self._create_event_and_artifact(
            'Test Event for single alert data lookup',
            cs1=testdata['alertruleid'],
            cs1Label=testdata['alertrulelabel'],
            cs2=testdata['alertruletimeframe'])

        # Pass self._action_result to poll with container id as argument
        ares = self._poll_for_success(self._action_result, container_id)

        # Assert that the call to RF was success
        self.assertEqual(ares['data'][0]['result_data'][0]['status'], 'success')

        # Assert summary has required fields of correct type
        self.assertIsInstance(ares['data'][0]['result_data'][0]['summary'][
                                  'returned_number_of_alerts'], int)
        self.assertIsInstance(ares['data'][0]['result_data'][0]['summary'][
                                  'total_number_of_alerts'], int)
        self.assertIsInstance(
            ares['data'][0]['result_data'][0]['summary']['rule_name'], unicode)
        self.assertIsInstance(
            ares['data'][0]['result_data'][0]['summary']['rule_id'], unicode)

        # Assert rule values in summary
        self.assertEquals(
            ares['data'][0]['result_data'][0]['summary']['rule_id'],
            testdata['alertruleid'])
        self.assertEquals(
            ares['data'][0]['result_data'][0]['summary']['rule_name'],
            testdata['alertrulename'])

        # Assert data properties if data is returned
        if len(ares['data'][0]['result_data'][0]['data']) > 0:
            # Assert alerts
            self.assertIsInstance(
                ares['data'][0]['result_data'][0]['data'][0]['alerts'], list)

            alert = ares['data'][0]['result_data'][0]['data'][0]['alerts'][0][
                'alert']
            self.assertIsInstance(alert['content'], dict)
            self.assertIsInstance(alert['entities'], dict)
            self.assertIsInstance(alert['alertTitle'], unicode)
            self.assertIsInstance(alert['alertUrl'], unicode)
            self.assertIsInstance(alert['triggered'], unicode)

            # Assert rule
            self.assertIsInstance(
                ares['data'][0]['result_data'][0]['data'][0]['rule'], dict)

            rule = ares['data'][0]['result_data'][0]['data'][0]['rule']
            self.assertEquals(rule['id'], testdata['alertruleid'])
            self.assertEquals(rule['name'], testdata['alertrulename'])

    def test_neg_alert_data_lookup_no_match(self):
        """Test behavior when passing alert query parameters that do not
        return data.
        """

        # Create container and artifact.
        testdata = {
            'alertruleid': 'KALLE',
            'alertrulelabel': 'alert rule id',
            'alertruletimeframe': 'anytime'
        }
        container_id = self._create_event_and_artifact(
            "Test Event for alert data event (bad rule id)",
            cs1=testdata['alertruleid'],
            cs1Label=testdata['alertrulelabel'],
            cs2=testdata['alertruletimeframe'])

        # Get action result
        ares = self._poll_for_success(self._action_result, container_id)

        # Assert we get empty values
        self.assertEqual(ares['data'][0]['result_data'][0]['summary'][
                             'total_number_of_alerts'], 0)

    def test_neg_alert_data_lookup_invalid_timeframe(self):
        """Test behavior when passing alert query parameters with invalid
        timeframe.
        """

        # Create container and artifact.
        testdata = {
            'alertruleid': 'VNPVFc',
            'alertrulelabel': 'alert rule id',
            'alertruletimeframe': 'kalle'
        }
        container_id = self._create_event_and_artifact(
            "Test Event for alert data event (bad rule id)",
            cs1=testdata['alertruleid'],
            cs1Label=testdata['alertrulelabel'],
            cs2=testdata['alertruletimeframe'])

        # Get action result
        ares = self._poll_for_success(self._action_result, container_id)

        # Assert we get a status failed
        self.assertEqual(ares['data'][0]['status'], 'failed')

        # Assert we get the server error message and status code included
        # in the response
        self.assertIsNotNone(re.search(
            "Failed parsing filter condition triggered = kalle.+400",
            ares['data'][0]['result_data'][0]['message']))
