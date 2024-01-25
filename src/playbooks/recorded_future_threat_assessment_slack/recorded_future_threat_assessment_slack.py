"""
This playbook has been created in connection with the Recorded Future App for Phantom version 2.1 to show how the new action "Threat Assessment" can be used in a playbook which acts on a event that have lists of IOCs stored as artifacts. 

Context is a required parameter for the new Threat Assessment action. A list of the possible contexts can be obtained through the other new action "list contexts" .

The playbook starts by marking the event as 'Open' before obtaining the assessment results from Recorded Future. If the artifacts are deemed malicious, the user gets a choice of whether to promote the event to a case, otherwise the event is closed.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug("on_start() called")

    # call 'initial_event_update' block
    initial_event_update(container=container)

    return


def initial_event_update(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("initial_event_update() called")

    phantom.set_status(container=container, status="Open")

    note_title = "Start of processing"
    note_content = ""
    phantom.add_note(
        container=container, note_type="general", title=note_title, content=note_content
    )
    threat_assessment_2(container=container)

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
            ["threat_assessment_2:action_result.data.*.verdict", "==", True],
        ],
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        prompt_1(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    # call connected blocks for 'else' condition 2
    close_event(
        action=action,
        success=success,
        container=container,
        results=results,
        handle=handle,
    )

    return


def format_1(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("format_1() called")

    template = """*Alert from testing Playbook*

> Event  {0} has been found to be malicious for context {1} with risk {3}
>
> The event has been promoted to a case for further investigation.
>
> Link to the event: {2}
> only testing parameter type {4}
> parameter name {5}"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "threat_assessment_2:action_result.parameter.threat_context",
        "container:url",
        "threat_assessment_2:action_result.data.*.max_riskscore",
        "threat_assessment_2:action_result.data.*.entities.*.type",
        "threat_assessment_2:action_result.data.*.name",
    ]

    phantom.format(
        container=container, template=template, parameters=parameters, name="format_1"
    )

    send_message_2(container=container)

    return


def close_event(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("close_event() called")

    note_title = "Recorded Future Threat Assessment result"
    note_content = "Event found not to be malicious and event closed."
    phantom.add_note(
        container=container, note_type="general", title=note_title, content=note_content
    )

    phantom.set_status(container=container, status="Closed")

    return


def threat_assessment_2(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("threat_assessment_2() called")

    # collect data for 'threat_assessment_2' call
    container_data = phantom.collect2(
        container=container,
        datapath=[
            "artifact:*.cef.destinationDnsDomain",
            "artifact:*.cef.fileHash",
            "artifact:*.cef.requestURL",
            "artifact:*.cef.destinationAddress",
            "artifact:*.id",
        ],
    )

    parameters = []

    # build parameters list for 'threat_assessment_2' call
    for container_item in container_data:
        parameters.append(
            {
                "domain": container_item[0],
                "hash": container_item[1],
                "url": container_item[2],
                "ip": container_item[3],
                "threshold_type": "",
                "threat_context": "c2",
                "threshold": "",
                # context (artifact id) is added to associate results with the artifact
                "context": {"artifact_id": container_item[4]},
            }
        )

    phantom.act(
        "threat assessment",
        parameters=parameters,
        assets=["recorded-future "],
        callback=decision_1,
        name="threat_assessment_2",
    )

    return


def send_message_2(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("send_message_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    # collect data for 'send_message_2' call
    formatted_data_1 = phantom.get_format_data(name="format_1")

    parameters = []

    # build parameters list for 'send_message_2' call
    parameters.append(
        {
            "message": formatted_data_1,
            "destination": "# phantom-demo",
        }
    )

    phantom.act(
        "send message",
        parameters=parameters,
        assets=["slack"],
        callback=promote_to_case,
        name="send_message_2",
    )

    return


def prompt_1(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Threat Assessment found malicious entities for the context: {0}.

Do you want to promote the event to a case for further investigation and send a notification in Slack?"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.cs1",
    ]

    # responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ],
            },
        },
    ]

    phantom.prompt2(
        container=container,
        user=user,
        message=message,
        respond_in_mins=30,
        name="prompt_1",
        parameters=parameters,
        response_types=response_types,
        callback=decision_2,
    )

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
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ],
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        format_1(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    # call connected blocks for 'else' condition 2
    increase_severity(
        action=action,
        success=success,
        container=container,
        results=results,
        handle=handle,
    )

    return


def increase_severity(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("increase_severity() called")

    note_title = "Recorded Future Threat Assessment result"
    note_content = "Event found to be malicious and its severity has been set to high. User declined to promote the event to a case."
    phantom.add_note(
        container=container, note_type="general", title=note_title, content=note_content
    )

    phantom.set_severity(container=container, severity="High")

    return


def promote_to_case(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("promote_to_case() called")

    note_title = "Recorded Future Threat Assessment result"
    note_content = "User initiated case promotion based on Recorded Future Assessment"
    phantom.add_note(
        container=container, note_type="general", title=note_title, content=note_content
    )

    phantom.promote(container=container, template="Data Breach")

    phantom.set_severity(container=container, severity="High")

    phantom.pin(
        container=container,
        data="",
        message="promoted to case",
        pin_type="card",
        pin_style="red",
        name=None,
    )

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
