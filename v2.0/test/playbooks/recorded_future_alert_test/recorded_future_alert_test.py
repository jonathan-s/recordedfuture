"""
Playbook created to test alert handling as defined in the Recorded Future app.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.cs1Label", "==", "alert rule id"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        alert_data_lookup_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.cs1Label", "==", "alert rule name"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        alert_rule_lookup_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def alert_data_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('alert_data_lookup_1() called')

    # collect data for 'alert_data_lookup_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.cs1', 'artifact:*.cef.cs2', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'alert_data_lookup_1' call
    for container_item in container_data:
        if container_item[0] and container_item[1]:
            parameters.append({
                'rule_id': container_item[0],
                'timeframe': container_item[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[2]},
            })

    phantom.act("alert data lookup", parameters=parameters, assets=['recorded-future'], callback=format_1, name="alert_data_lookup_1")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "alert_data_lookup_1:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    add_comment_1(container=container)

    return

def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_comment_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_1')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def alert_rule_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('alert_rule_lookup_1() called')

    # collect data for 'alert_rule_lookup_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.cs1', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'alert_rule_lookup_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'rule_name': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("alert rule lookup", parameters=parameters, assets=['recorded-future'], callback=format_2, name="alert_rule_lookup_1")

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "alert_rule_lookup_1:action_result.summary.rule_id_list",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    add_comment_2(container=container)

    return

def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_comment_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_2')

    phantom.comment(container=container, comment=formatted_data_1)

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