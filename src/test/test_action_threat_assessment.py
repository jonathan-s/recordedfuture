"""Test suite for domain reputation action"""
import os
import logging
import requests
from test_harness import RfTests
import rfapi

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_threat_assessment_test'


class RfThreatAssessmentTests(RfTests):
    """Test cases for threat assessment action."""

    def setUp(self, playbook=None):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    def test_threat_assessment(self):
        """Test behavior when a single ip is supplied."""
        # Grab a list of which entity types are used in each context.
        conapi = rfapi.ConnectApiClient(auth=os.environ['RF_TOKEN'],
                                  app_name='phantom_unittests')
        ctxlist = conapi._query('soar/triage/contexts')
        for context in ['c2', 'cnc', 'phishing']:
            if 'c2' not in ctxlist.result:
                datagroups = ctxlist.result['cnc']['datagroup'].keys()
            else:
                datagroups = ctxlist.result[context]['datagroup'].keys()
            for datagroup in datagroups:
                targets = self._get_triage_entities_by_group(
                    datagroup,
                    '%sSubscore' % context,
                    5, 79, 100)
                print('%s / %s: %d' % (context, datagroup, len(targets)))
        self.assertIsNone(targets, 'TARGETS: %s' % targets)
