"""Test suite for ip reputation action"""
import logging
import requests
from test_harness import RfTests

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_alert_test'
TARGETS = [
    ('recordedfuture.com Leaked Credentials Document', ['VNPVFc']),
    ('Recorded', [u'Ya4pFB', u'YcKufV', u'Vp5IXy', u'VNPVFc', u'VKhgWu',
                  u'Vp5IXx', u'YcKufW', u'Ya9Aof', u'YbYAKE', u'aRE2MK'
                  ])
]


class RfRuleIdLookupTests(RfTests):
    """Test cases for ip reputation action."""

    def setUp(self, playbook=None):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def _test_alert_fule_id_lookup_rule_id(self, freetext, rule_id_list, cname):
        """Verify that the freetext search yields the right set of rule ids."""
        # Create container and artifact.
        container_id = self._create_event_and_artifact(
            cname, cs1=freetext, cs1Label="alert rule name")

        # Fetch the result of the automatic run.
        ares = self._poll_for_success(self._action_result, container_id)

        result_data = ares['data'][0]['result_data'][0]['data']
        result_rule_id_list = [result['rule']['id'] for result in result_data]
        self.assertEqual(set(rule_id_list), set(result_rule_id_list))

    def test_rule_id_lookup(self):
        """Verify that a freetext search finds the proper rule ids."""
        for freetext, rule_id_list in TARGETS:
            self._test_alert_fule_id_lookup_rule_id(
                freetext, rule_id_list,
                "Test Event for alert rule lookup event")

    def test_no_match_rule_id_lookup(self):
        """Verify that a freetext search without any match returns empty list.
        """
        self._test_alert_fule_id_lookup_rule_id(
            'Tardis', [],
            'Test Event for alert rule lookup event without match')
