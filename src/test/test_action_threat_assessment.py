"""Test suite for domain reputation action"""
import os
import logging
import unittest
import requests
from test_harness import RfTests
import rfapi

# disable certificate warnings for self signed certificates
requests.packages.urllib3.disable_warnings()

# Test these contexts
CTXLIST = ['c2', 'phishing']
THRESHOLD = 60

# Logger
LOGGER = logging.getLogger(__name__)

PBOOK = 'recorded_future_threat_assessment_test'
TESTDATA = dict(destinationAddress=['8.8.8.8'],
                destinationDnsDomain=['example.com'],
                fileHash=['d41d8cd98f00b204e9800998ecf8427e'],  # emtpty file
                requestURL=['https://www.example.com'])
DGTOCEF = {
    'ip': 'destinationAddress',
    'domain': 'destinationDnsDomain',
    'hash': 'fileHash',
    'url': 'requestURL'
}


class RfThreatAssessmentTests(RfTests):
    """Test cases for threat assessment action."""

    def setUp(self, playbook=None):
        """Setup test environment."""
        RfTests.setUp(self, PBOOK)

    # @unittest.skip('Lacking testable events for some data groups.')
    def test_threat_assessment_testability(self):
        """Check that all contexts are testable.

        If there are no entities available in any of the used entity types
        in a context with high enough risk it is not possible to test
        a positive verdict.
        """
        # Grab a list of which entity types are used in each context.
        conapi = rfapi.ConnectApiClient(auth=os.environ['RF_TOKEN'],
                                        app_name='phantom_unittests')
        ctxlist = conapi._query('soar/triage/contexts')
        for context in CTXLIST:
            datagroups = ctxlist.result[context]['datagroup'].keys()
            # threshold = ctxlist.result[context]['default_threshold']
            threshold = THRESHOLD
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

    # @unittest.skip('Debug')
    def test_threat_assessment_positive_verdict(self):
        """Check that entities with sufficient risk yields positive verdict.

        "Randomly" select at least one entity with sufficient risk for the
        context and add it along with other entities to an artifact within
        a container. Run the playbook. Examine result."""
        conapi = rfapi.ConnectApiClient(auth=os.environ['RF_TOKEN'],
                                        app_name='phantom_unittests')
        ctxlist = conapi._query('soar/triage/contexts')
        print('contexts: %s' % CTXLIST)
        for context in CTXLIST:
            datagroups = ctxlist.result[context]['datagroup'].keys()
            # threshold = ctxlist.result[context]['default_threshold']
            threshold = THRESHOLD
            threshold_type = 'max'

            print('datagroups %s: %s' % (context, datagroups))
            for datagroup in datagroups:
                targets = self._get_triage_entities_by_group(
                    datagroup,
                    '%sSubscore' % context,
                    5, threshold - 1, 100)

                print('targets %s/%s: %s' % (context, datagroup, targets))
                if not targets:
                    self.assertTrue(False, '%s/%s: no targets found.'
                                    % (context, datagroup))
                else:
                    target = targets[0].split(':', 1)[1]
                    self._test_positive_verdict(context, datagroup,
                                                target, threshold,
                                                threshold_type)

    def _create_threat_assessment_event(self,
                                        context, datagroup, target,
                                        threshold, threshold_type):
        """Create a threat assessment event for testing.

        The event is expected to be consumed by the
        recorded_future_threat_assessment_test playbook."""
        # Make a copy of the test_data
        test_data = dict(**TESTDATA)
        test_data['cs1'] = context
        test_data['cs1Label'] = 'Threat Assessment Context'
        test_data['cs2'] = threshold
        test_data['cs2Label'] = 'Threshold'
        test_data['cs3'] = threshold_type
        test_data['cs3Label'] = 'Threshold Type'
        test_data[DGTOCEF[datagroup]].append(target)

        # Reformat lists into comma separated strings
        for key in ['ip', 'domain', 'hash', 'url']:
            test_data[DGTOCEF[key]] = ','.join(
                test_data[DGTOCEF[key]])
        print('test_data %s/%s/%s: %s' % (context,
                                          datagroup,
                                          target,
                                          test_data
                                          ))

        # Create container with artifact
        container_id = self._create_event_and_artifact(
            'Test Event Threat Assessment (%s/%s)'
            % (context, datagroup),
            **test_data)

        # Wait for finished playbook run and collect result.
        ares = self._poll_for_success(self._action_result,
                                      container_id)
        return ares

    def _test_positive_verdict(self,
                               context, datagroup, target,
                               threshold, threshold_type):
        """Test positive verdict."""
        # Create event and collect playbook result
        ares = self._create_threat_assessment_event(context, datagroup,
                                                    target, threshold,
                                                    threshold_type)
        # Verify the verdict
        verdict = ares['data'][0]['result_data'][0]['data'][0][
            'verdict']
        self.assertEqual(verdict, True, '%s/%s did not yield true verdict'
                         % (context, datagroup))
