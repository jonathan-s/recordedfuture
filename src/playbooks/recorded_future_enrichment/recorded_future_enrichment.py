"""
This playbook was created to show how to obtain intelligence for IP address with a high Risk Score. It is typically used for artifact enrichment.

The playbook has been updated to work in conjunction with Recorded Future App for Phantom v2.0.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug("on_start() called")

    # call 'ip_intelligence_2' block
    ip_intelligence_2(container=container)

    return


def filter_for_risk_score_above_90(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("filter_for_risk_score_above_90() called")

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_2:action_result.data.*.risk.score", ">=", 90],
            [
                "ip_intelligence_2:action_result.data.*.risk.evidenceDetails.*.rule",
                "in",
                "Actively Communicating C&C Server",
            ],
        ],
        logical_operator="and",
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        format_email(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        return

    # call connected blocks for 'else' condition 2

    return


def send_email(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("send_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    # collect data for 'send_email' call
    formatted_data_1 = phantom.get_format_data(name="format_email")

    parameters = []

    # build parameters list for 'send_email' call
    parameters.append(
        {
            "body": formatted_data_1,
            "from": "phantom@example.com",
            "attachments": "",
            "headers": "",
            "cc": "",
            "bcc": "",
            "to": "",
            "subject": "Alert from Recorded Futures App for Phantom - enrichment playbook",
        }
    )

    phantom.act(
        "send email",
        parameters=parameters,
        assets=["smtp"],
        callback=add_bad_ip_to_list,
        name="send_email",
    )

    return


def format_email(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("format_email() called")

    template = """IP address *{0}*  is has a risk score of *{1}*

The rules triggered for this IP are *{2}*

The Evidence Details are:
{3}

More information about the entity:{4}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_2:action_result.parameter.ip",
        "ip_intelligence_2:action_result.data.*.risk.score",
        "ip_intelligence_2:action_result.data.*.risk.evidenceDetails.*.rule",
        "ip_intelligence_2:action_result.data.*.risk.evidenceDetails.*.evidenceString",
        "ip_intelligence_2:action_result.data.*.intelCard",
    ]

    phantom.format(
        container=container,
        template=template,
        parameters=parameters,
        name="format_email",
    )

    send_email(container=container)

    return


def add_bad_ip_to_list(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("add_bad_ip_to_list() called")

    container_data = phantom.collect2(
        container=container,
        datapath=["artifact:*.cef.destinationAddress", "artifact:*.id"],
    )

    container_item_0 = [item[0] for item in container_data]

    phantom.add_list("Identified IP's", container_item_0)

    return


def ip_intelligence_2(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("ip_intelligence_2() called")

    # collect data for 'ip_intelligence_2' call
    container_data = phantom.collect2(
        container=container,
        datapath=["artifact:*.cef.destinationAddress", "artifact:*.id"],
    )

    parameters = []

    # build parameters list for 'ip_intelligence_2' call
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
        "ip intelligence",
        parameters=parameters,
        assets=["recorded-future"],
        callback=filter_for_risk_score_above_90,
        name="ip_intelligence_2",
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
