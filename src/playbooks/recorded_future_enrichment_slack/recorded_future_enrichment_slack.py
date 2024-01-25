"""
This playbook was created to show how to obtain intelligence for IP address with a high Risk Score. It is typically used for artifact enrichment.\n\nThe playbook has been updated to work in conjunction with Recorded Future App for Phantom v3.1.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug("on_start() called")

    # call 'lookup_ip_intelligence' block
    lookup_ip_intelligence(container=container)

    return


def lookup_ip_intelligence(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
    custom_function=None,
    **kwargs,
):
    phantom.debug("lookup_ip_intelligence() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(
        container=container,
        datapath=["artifact:*.cef.destinationAddress", "artifact:*.id"],
    )

    parameters = []

    # build parameters list for 'lookup_ip_intelligence' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append(
                {
                    "ip": container_artifact_item[0],
                    "context": {"artifact_id": container_artifact_item[1]},
                }
            )

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act(
        "ip intelligence",
        parameters=parameters,
        name="lookup_ip_intelligence",
        assets=["recorded-future"],
        callback=inspect_risk,
    )

    return


def inspect_risk(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
    custom_function=None,
    **kwargs,
):
    phantom.debug("inspect_risk() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["lookup_ip_intelligence:action_result.data.*.risk.score", ">=", 90]
        ],
    )

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_slack_message(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    return


def format_slack_message(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
    custom_function=None,
    **kwargs,
):
    phantom.debug("format_slack_message() called")

    template = """*Alert from Recorded Futures App for Phantom - enrichment playbook*\n\n>IP address *{0}*  is has a risk score of *{1}*\n>\n>The rules triggered for this IP are *{2}*\n>\n>The Evidence Details are:\n>{3}\n>\n>More information about the entity: {4}"""

    # parameter list for template variable replacement
    parameters = [
        "lookup_ip_intelligence:action_result.parameter.ip",
        "lookup_ip_intelligence:action_result.data.*.risk.score",
        "lookup_ip_intelligence:action_result.data.*.risk.evidenceDetails.*.rule",
        "lookup_ip_intelligence:action_result.data.*.risk.evidenceDetails.*.evidenceString",
        "lookup_ip_intelligence:action_result.data.*.intelCard",
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(
        container=container,
        template=template,
        parameters=parameters,
        name="format_slack_message",
    )

    send_slack_message(container=container)

    return


def send_slack_message(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
    custom_function=None,
    **kwargs,
):
    phantom.debug("send_slack_message() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_slack_message = phantom.get_format_data(name="format_slack_message")

    parameters = []

    if format_slack_message is not None:
        parameters.append(
            {
                "message": format_slack_message,
                "destination": "# phantom-demo",
            }
        )

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act(
        "send message",
        parameters=parameters,
        name="send_slack_message",
        assets=["slack"],
        callback=add_bad_ip_to_list,
    )

    return


def add_bad_ip_to_list(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
    custom_function=None,
    **kwargs,
):
    phantom.debug("add_bad_ip_to_list() called")

    container_artifact_data = phantom.collect2(
        container=container, datapath=["artifact:*.cef.destinationAddress"]
    )

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_list(list_name="Identified IP's", values=container_artifact_cef_item_0)

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
