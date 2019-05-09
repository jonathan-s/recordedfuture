"""
Playbook created to test IP reputation action as defined in the Recorded Future app.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'alert_data_lookup_1' block
    alert_data_lookup_1(container=container)

    return

def alert_data_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('alert_data_lookup_1() called')

    id_value = container.get('id', None)

    # collect data for 'alert_data_lookup_1' call

    parameters = []
    
    # build parameters list for 'alert_data_lookup_1' call
    parameters.append({
        'rule_id': id_value,
        'timeframe': "-24h to now",
    })

    phantom.act("alert data lookup", parameters=parameters, assets=['recordedfuture'], name="alert_data_lookup_1")

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