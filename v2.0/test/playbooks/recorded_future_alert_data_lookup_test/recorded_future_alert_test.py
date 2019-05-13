"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def rule_id_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('rule_id_lookup_1() called')

    # collect data for 'rule_id_lookup_1' call

    parameters = []
    
    # build parameters list for 'rule_id_lookup_1' call
    parameters.append({
        'rule_name': "Recorded",
    })

    phantom.act("rule id lookup", parameters=parameters, assets=['recordedfuture'], callback=alert_data_lookup_1, name="rule_id_lookup_1")

    return

def alert_data_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('alert_data_lookup_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'alert_data_lookup_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['rule_id_lookup_1:action_result.data.*.rule.id', 'rule_id_lookup_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'alert_data_lookup_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'rule_id': results_item_1[0],
                'timeframe': "-24h to now",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("alert data lookup", parameters=parameters, assets=['recordedfuture'], name="alert_data_lookup_1", parent_action=action)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.cs1Label", "==", "alert rule name"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        rule_id_lookup_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.cs1Label", "==", "alert rule id"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        alert_data_lookup_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 3

    return

def alert_data_lookup_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('alert_data_lookup_2() called')

    # collect data for 'alert_data_lookup_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.cs1', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'alert_data_lookup_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'rule_id': container_item[0],
                'timeframe': "-24h to now",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("alert data lookup", parameters=parameters, assets=['recordedfuture'], name="alert_data_lookup_2")

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