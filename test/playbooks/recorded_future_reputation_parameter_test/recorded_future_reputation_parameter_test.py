"""
Playbook used to test the intelligence methods of the Recorded Future app.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug("on_start() called")

    # call 'ip_reputation_4' block
    ip_reputation_4(container=container)

    # call 'domain_reputation_3' block
    domain_reputation_3(container=container)

    # call 'file_reputation_4' block
    file_reputation_4(container=container)

    # call 'vulnerability_reputation_3' block
    vulnerability_reputation_3(container=container)

    # call 'url_reputation_4' block
    url_reputation_4(container=container)

    return


def IP_Reputation_Parameters(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("IP_Reputation_Parameters() called")

    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Reputation: 

Entity: {1}
Risk score: {2}
Rules: {3}

Entity has triggered {4} of {5} rules

Also summary score {6}
Summary level {7}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation_4:action_result.data.*.type",
        "ip_reputation_4:action_result.data.*.name",
        "ip_reputation_4:action_result.data.*.evidence.*.rule",
        "ip_reputation_4:action_result.data.*.riskscore",
        "ip_reputation_4:action_result.data.*.rulecount",
        "ip_reputation_4:action_result.data.*.maxrules",
        "ip_reputation_4:action_result.summary.riskscore",
        "ip_reputation_4:action_result.summary.risklevel",
    ]

    # responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(
        container=container,
        user=user,
        message=message,
        respond_in_mins=30,
        name="IP_Reputation_Parameters",
        parameters=parameters,
        response_types=response_types,
    )

    return


def Domain_Reputation_Parameters(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("Domain_Reputation_Parameters() called")

    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Reputation: 

Entity: {1}
Risk score: {2}
Rules: {3}

Entity has triggered {4} of {5} rules

Also summary score {6}
Summary level {7}"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation_3:action_result.data.*.type",
        "domain_reputation_3:action_result.data.*.name",
        "domain_reputation_3:action_result.summary.riskscore",
        "domain_reputation_3:action_result.data.*.evidence.*.rule",
        "domain_reputation_3:action_result.data.*.rulecount",
        "domain_reputation_3:action_result.data.*.maxrules",
        "domain_reputation_3:action_result.summary.riskscore",
        "domain_reputation_3:action_result.summary.risklevel",
    ]

    # responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(
        container=container,
        user=user,
        message=message,
        respond_in_mins=30,
        name="Domain_Reputation_Parameters",
        parameters=parameters,
        response_types=response_types,
    )

    return


def File_Reputation_Parameters(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("File_Reputation_Parameters() called")

    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Reputation: 

Entity: {1}
Risk score: {2}
Rules: {3}

Entity has triggered {4} of {5} rules

Also summary score {6}
Summary level {7}"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_4:action_result.data.*.type",
        "file_reputation_4:action_result.data.*.name",
        "file_reputation_4:action_result.data.*.riskscore",
        "file_reputation_4:action_result.data.*.evidence.*.rule",
        "file_reputation_4:action_result.data.*.rulecount",
        "file_reputation_4:action_result.data.*.maxrules",
        "file_reputation_4:action_result.summary.riskscore",
        "file_reputation_4:action_result.summary.risklevel",
    ]

    # responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(
        container=container,
        user=user,
        message=message,
        respond_in_mins=30,
        name="File_Reputation_Parameters",
        parameters=parameters,
        response_types=response_types,
    )

    return


def Vulnerability_Reputation_Parameters(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("Vulnerability_Reputation_Parameters() called")

    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Reputation: 

Entity: {1}
Risk score: {2}
Rules: {3}

Entity has triggered {4} of {5} rules

Also summary score {6}
Summary level {7}"""

    # parameter list for template variable replacement
    parameters = [
        "vulnerability_reputation_3:action_result.data.*.type",
        "vulnerability_reputation_3:action_result.data.*.name",
        "vulnerability_reputation_3:action_result.data.*.riskscore",
        "vulnerability_reputation_3:action_result.data.*.evidence.*.rule",
        "vulnerability_reputation_3:action_result.data.*.rulecount",
        "vulnerability_reputation_3:action_result.data.*.maxrules",
        "vulnerability_reputation_3:action_result.summary.riskscore",
        "vulnerability_reputation_3:action_result.summary.risklevel",
    ]

    # responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(
        container=container,
        user=user,
        message=message,
        respond_in_mins=30,
        name="Vulnerability_Reputation_Parameters",
        parameters=parameters,
        response_types=response_types,
    )

    return


def URL_Reputation_Parameters(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("URL_Reputation_Parameters() called")

    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Output parameters from {0} Reputation: 

Entity: {1}
Risk score: {2}
Rules: {3}

Entity has triggered {4} of {5} rules

Also summary score {6}
Summary level {7}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_4:action_result.data.*.type",
        "url_reputation_4:action_result.data.*.name",
        "url_reputation_4:action_result.data.*.riskscore",
        "url_reputation_4:action_result.data.*.evidence.*.rule",
        "url_reputation_4:action_result.data.*.rulecount",
        "url_reputation_4:action_result.data.*.maxrules",
        "url_reputation_4:action_result.summary.riskscore",
        "url_reputation_4:action_result.summary.risklevel",
    ]

    # responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(
        container=container,
        user=user,
        message=message,
        respond_in_mins=30,
        name="URL_Reputation_Parameters",
        parameters=parameters,
        response_types=response_types,
    )

    return


def ip_reputation_4(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("ip_reputation_4() called")

    # collect data for 'ip_reputation_4' call
    container_data = phantom.collect2(
        container=container,
        datapath=["artifact:*.cef.destinationAddress", "artifact:*.id"],
    )

    parameters = []

    # build parameters list for 'ip_reputation_4' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append(
                {
                    "ip": container_item[0],
                    # context (artifact id) is added to associate results with the artifact
                    "context": {"artifact_id": container_item[1]},
                }
            )

    phantom.act(
        "ip reputation",
        parameters=parameters,
        assets=["recorded-future "],
        callback=decision_1,
        name="ip_reputation_4",
    )

    return


def domain_reputation_3(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("domain_reputation_3() called")

    # collect data for 'domain_reputation_3' call
    container_data = phantom.collect2(
        container=container,
        datapath=["artifact:*.cef.destinationDnsDomain", "artifact:*.id"],
    )

    parameters = []

    # build parameters list for 'domain_reputation_3' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append(
                {
                    "domain": container_item[0],
                    # context (artifact id) is added to associate results with the artifact
                    "context": {"artifact_id": container_item[1]},
                }
            )

    phantom.act(
        "domain reputation",
        parameters=parameters,
        assets=["recorded-future "],
        callback=decision_2,
        name="domain_reputation_3",
    )

    return


def file_reputation_4(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("file_reputation_4() called")

    # collect data for 'file_reputation_4' call
    container_data = phantom.collect2(
        container=container, datapath=["artifact:*.cef.fileHash", "artifact:*.id"]
    )

    parameters = []

    # build parameters list for 'file_reputation_4' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append(
                {
                    "hash": container_item[0],
                    # context (artifact id) is added to associate results with the artifact
                    "context": {"artifact_id": container_item[1]},
                }
            )

    phantom.act(
        "file reputation",
        parameters=parameters,
        assets=["recorded-future "],
        callback=decision_3,
        name="file_reputation_4",
    )

    return


def vulnerability_reputation_3(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("vulnerability_reputation_3() called")

    # collect data for 'vulnerability_reputation_3' call
    container_data = phantom.collect2(
        container=container, datapath=["artifact:*.cef.cs1", "artifact:*.id"]
    )

    parameters = []

    # build parameters list for 'vulnerability_reputation_3' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append(
                {
                    "vulnerability": container_item[0],
                    # context (artifact id) is added to associate results with the artifact
                    "context": {"artifact_id": container_item[1]},
                }
            )

    phantom.act(
        "vulnerability reputation",
        parameters=parameters,
        assets=["recorded-future "],
        callback=decision_4,
        name="vulnerability_reputation_3",
    )

    return


def url_reputation_4(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("url_reputation_4() called")

    # collect data for 'url_reputation_4' call
    container_data = phantom.collect2(
        container=container, datapath=["artifact:*.cef.requestURL", "artifact:*.id"]
    )

    parameters = []

    # build parameters list for 'url_reputation_4' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append(
                {
                    "url": container_item[0],
                    # context (artifact id) is added to associate results with the artifact
                    "context": {"artifact_id": container_item[1]},
                }
            )

    phantom.act(
        "url reputation",
        parameters=parameters,
        assets=["recorded-future "],
        callback=decision_5,
        name="url_reputation_4",
    )

    return


def decision_1(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_4:action_result.data.*.riskscore", ">", 0],
        ],
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        IP_Reputation_Parameters(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    return


def decision_2(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_3:action_result.data.*.riskscore", ">", 0],
        ],
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Domain_Reputation_Parameters(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    return


def decision_3(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_4:action_result.data.*.riskscore", ">", 0],
        ],
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        File_Reputation_Parameters(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    return


def decision_4(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("decision_4() called")

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["vulnerability_reputation_3:action_result.data.*.riskscore", ">", 0],
        ],
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Vulnerability_Reputation_Parameters(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    return


def decision_5(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("decision_5() called")

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_4:action_result.data.*.riskscore", ">", 0],
        ],
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        URL_Reputation_Parameters(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
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
