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
        """Check that all contexts are testable.

        If there are no entities available in any of the used entity types
        in a context with high enough risk it is not possible to test
        a positive verdict.
        """
        # Grab a list of which entity types are used in each context.
        conapi = rfapi.ConnectApiClient(auth=os.environ['RF_TOKEN'],
                                        app_name='phantom_unittests')
        ctxlist = conapi._query('soar/triage/contexts')
        for context in ['c2', 'cnc', 'phishing']:
            if 'c2' not in ctxlist.result:  # cnc is migrating to c2
                datagroups = ctxlist.result['cnc']['datagroup'].keys()
                threshold = ctxlist.result['cnc']['default_threshold']
            else:
                datagroups = ctxlist.result[context]['datagroup'].keys()
                threshold = ctxlist.result[context]['default_threshold']
            total_targets = 0
            for datagroup in datagroups:
                targets = self._get_triage_entities_by_group(
                    datagroup,
                    '%sSubscore' % context,
                    5, threshold - 1, 100)
                total_targets += len(targets)
                # print('%s / %s: %d' % (context, datagroup, len(targets)))
            self.assertNotEqual(total_targets, 0,
                                'Context "%s" cannot be '
                                'tested, there are no entities in any group '
                                'that can produce a positive verdict.'
                                % context)
