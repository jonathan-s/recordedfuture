"""
Playbook used to test the intelligence methods of the Recorded Future app.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'ip_intelligence_1' block
    ip_intelligence_1(container=container)

    # call 'domain_intelligence_1' block
    domain_intelligence_1(container=container)

    # call 'file_intelligence_1' block
    file_intelligence_1(container=container)

    # call 'vulnerability_intelligence_1' block
    vulnerability_intelligence_1(container=container)

    # call 'url_intelligence_1' block
    url_intelligence_1(container=container)

    return

def IP_Intelligence_Parameters(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('IP_Intelligence_Parameters() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Intelligence: 

Entity: {1}
Risk score: {2}
Rules: {3}

{4}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.data.*.entity.type",
        "ip_intelligence_1:action_result.data.*.entity.name",
        "ip_intelligence_1:action_result.data.*.risk.score",
        "ip_intelligence_1:action_result.data.*.risk.evidenceDetails.*.rule",
        "ip_intelligence_1:action_result.data.*.risk.riskSummary",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="IP_Intelligence_Parameters", parameters=parameters, response_types=response_types)

    return

def Domain_Intelligence_Parameters(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Domain_Intelligence_Parameters() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Intelligence: 

Entity: {1}
Risk score: {2}
Rules: {3}

{4}"""

    # parameter list for template variable replacement
    parameters = [
        "domain_intelligence_1:action_result.data.*.entity.type",
        "domain_intelligence_1:action_result.data.*.entity.name",
        "domain_intelligence_1:action_result.data.*.risk.score",
        "domain_intelligence_1:action_result.data.*.risk.evidenceDetails.*.rule",
        "domain_intelligence_1:action_result.data.*.risk.riskSummary",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Domain_Intelligence_Parameters", parameters=parameters, response_types=response_types)

    return

def File_Intelligence_Parameters(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('File_Intelligence_Parameters() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Intelligence: 

Entity: {1}
Risk score: {2}
Rules: {3}

{4}"""

    # parameter list for template variable replacement
    parameters = [
        "file_intelligence_1:action_result.data.*.entity.type",
        "file_intelligence_1:action_result.data.*.entity.name",
        "file_intelligence_1:action_result.data.*.risk.score",
        "file_intelligence_1:action_result.data.*.risk.evidenceDetails.*.rule",
        "file_intelligence_1:action_result.data.*.risk.riskSummary",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="File_Intelligence_Parameters", parameters=parameters, response_types=response_types)

    return

def Vulnerability_Intelligence_Parameters(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Vulnerability_Intelligence_Parameters() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Intelligence: 

Entity: {1}
Risk score: {2}
Rules: {3}

{4}"""

    # parameter list for template variable replacement
    parameters = [
        "vulnerability_intelligence_1:action_result.data.*.entity.type",
        "vulnerability_intelligence_1:action_result.data.*.entity.name",
        "vulnerability_intelligence_1:action_result.data.*.risk.score",
        "vulnerability_intelligence_1:action_result.data.*.risk.evidenceDetails.*.rule",
        "vulnerability_intelligence_1:action_result.data.*.risk.riskSummary",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Vulnerability_Intelligence_Parameters", parameters=parameters, response_types=response_types)

    return

def URL_Intelligence_Parameters(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('URL_Intelligence_Parameters() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Intelligence: 

Entity: {1}
Risk score: {2}
Rules: {3}

{4}"""

    # parameter list for template variable replacement
    parameters = [
        "url_intelligence_1:action_result.data.*.entity.type",
        "url_intelligence_1:action_result.data.*.entity.name",
        "url_intelligence_1:action_result.data.*.risk.score",
        "url_intelligence_1:action_result.data.*.risk.evidenceDetails.*.rule",
        "url_intelligence_1:action_result.data.*.risk.riskSummary",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="URL_Intelligence_Parameters", parameters=parameters, response_types=response_types)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.risk.score", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        IP_Intelligence_Parameters(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_intelligence_1:action_result.data.*.risk.score", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Domain_Intelligence_Parameters(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_intelligence_1:action_result.data.*.risk.score", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        File_Intelligence_Parameters(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["vulnerability_intelligence_1:action_result.data.*.risk.score", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Vulnerability_Intelligence_Parameters(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_intelligence_1:action_result.data.*.risk.score", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        URL_Intelligence_Parameters(action=action, success=success, container=container, results=results, handle=handle)
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

    phantom.act("ip intelligence", parameters=parameters, assets=['recorded-future '], callback=decision_1, name="ip_intelligence_1")

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

    phantom.act("domain intelligence", parameters=parameters, assets=['recorded-future '], callback=decision_2, name="domain_intelligence_1")

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

    phantom.act("file intelligence", parameters=parameters, assets=['recorded-future '], callback=decision_3, name="file_intelligence_1")

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

    phantom.act("vulnerability intelligence", parameters=parameters, assets=['recorded-future '], callback=decision_4, name="vulnerability_intelligence_1")

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

    phantom.act("url intelligence", parameters=parameters, assets=['recorded-future '], callback=decision_5, name="url_intelligence_1")

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