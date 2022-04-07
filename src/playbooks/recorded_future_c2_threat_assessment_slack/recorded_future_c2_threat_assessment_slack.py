"""
This playbook has been created in connection with the Recorded Future App for Phantom version 3.1 to show how the action &quot;Threat Assessment&quot; can be used in a playbook which acts on a event that have lists of IOCs stored as artifacts. \n\nContext is a required parameter for the new Threat Assessment action. A list of the possible contexts can be obtained through the other new action &quot;list contexts&quot; .  The parameter can make use of an artifact but this playbook works solely on C2.\n\nThe playbook starts by marking the event as &#39;Open&#39; before obtaining the assessment results from Recorded Future. If the artifacts are deemed malicious, the user gets a choice of whether to promote the event to a case, otherwise the event is closed.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_status_to_open' block
    set_status_to_open(container=container)

    return

def set_status_to_open(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_status_to_open() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="open")
    phantom.add_note(container=container, note_format="html", note_type="general", title="Start of Processing")

    container = phantom.get_container(container.get('id', None))

    c2_threat_assessment(container=container)

    return


def c2_threat_assessment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("c2_threat_assessment() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.destinationDnsDomain","artifact:*.cef.requestURL","artifact:*.cef.fileHash","artifact:*.id"])

    parameters = []

    # build parameters list for 'c2_threat_assessment' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "ip": container_artifact_item[0],
            "domain": container_artifact_item[1],
            "url": container_artifact_item[2],
            "hash": container_artifact_item[3],
            "threat_context": "c2",
            "context": {'artifact_id': container_artifact_item[4]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("threat assessment", parameters=parameters, name="c2_threat_assessment", assets=["recorded-future"], callback=decision_1)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["c2_threat_assessment:action_result.data.*.verdict", "==", True]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_slack_message(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    close_event(action=action, success=success, container=container, results=results, handle=handle)

    return


def format_slack_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_slack_message() called")

    template = """*Alert from testing Playbook*\n\n> Event  {0} has been found to be malicious for context {1} with risk {3}\n>\n> The event has been promoted to a case for further investigation.\n>\n> Link to the event: {2}"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "c2_threat_assessment:action_result.parameter.threat_context",
        "container:url",
        "c2_threat_assessment:action_result.data.*.triage_riskscore"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_slack_message")

    send_slack_message(container=container)

    return


def send_slack_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_slack_message() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_slack_message = phantom.get_format_data(name="format_slack_message")

    parameters = []

    if format_slack_message is not None:
        parameters.append({
            "message": format_slack_message,
            "destination": "# phantom-demo",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send message", parameters=parameters, name="send_slack_message", assets=["slack"], callback=set_severity_high)

    return


def set_severity_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_high() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    return


def close_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_event() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return