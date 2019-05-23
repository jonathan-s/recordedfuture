"""
Playbook used to test the intelligence methods of the Recorded Future app.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        file_intelligence_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        url_intelligence_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ])

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        ip_intelligence_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ])

    # call connected blocks if condition 4 matched
    if matched_artifacts_4 or matched_results_4:
        domain_intelligence_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.cs1Label", "==", "vulnerability"],
            ["artifact:*.cef.cs1", "!=", ""],
        ],
        logical_operator='and')

    # call connected blocks if condition 5 matched
    if matched_artifacts_5 or matched_results_5:
        vulnerability_intelligence_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def ip_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_intelligence_1() called')

    # collect data for 'ip_intelligence_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_intelligence_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("ip intelligence", parameters=parameters, assets=['recordedfuture'], name="ip_intelligence_1")

    return

def file_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_intelligence_1() called')

    # collect data for 'file_intelligence_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_intelligence_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file intelligence", parameters=parameters, assets=['recordedfuture'], name="file_intelligence_1")

    return

def domain_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_intelligence_1() called')

    # collect data for 'domain_intelligence_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_intelligence_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("domain intelligence", parameters=parameters, assets=['recordedfuture'], name="domain_intelligence_1")

    return

def vulnerability_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('vulnerability_intelligence_1() called')

    # collect data for 'vulnerability_intelligence_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.cs1', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'vulnerability_intelligence_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'vulnerability': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("vulnerability intelligence", parameters=parameters, assets=['recordedfuture'], name="vulnerability_intelligence_1")

    return

def url_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_intelligence_1() called')

    # collect data for 'url_intelligence_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_intelligence_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("url intelligence", parameters=parameters, assets=['recordedfuture'], name="url_intelligence_1")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')
    
    tags_param = container.get('tags', None)

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            [tags_param, "==", ['recorded_future_intelligence_test']],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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