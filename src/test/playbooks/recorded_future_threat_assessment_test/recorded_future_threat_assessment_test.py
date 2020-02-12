"""
Playbook used to test the threat assessment methods of the Recorded Future app.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'threat_assessment_1' block
    threat_assessment_1(container=container)

    return

def threat_assessment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('threat_assessment_1() called')

    # collect data for 'threat_assessment_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.cef.fileHashMd5', 'artifact:*.cef.requestURL', 'artifact:*.cef.destinationAddress', 'artifact:*.cef.cs3', 'artifact:*.cef.cs1', 'artifact:*.cef.cs2', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'threat_assessment_1' call
    for container_item in container_data:
        parameters.append({
            'domain': container_item[0],
            'hash': container_item[1],
            'url': container_item[2],
            'ip': container_item[3],
            'threshold_type': container_item[4],
            'threat_context': container_item[5],
            'threshold': container_item[6],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[7]},
        })

    phantom.act("threat assessment", parameters=parameters, assets=['recorded-future'], name="threat_assessment_1")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return