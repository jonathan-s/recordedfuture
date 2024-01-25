"""
This playbook checks the reputation of an IP address and, based on its Risk Score, forwards it to Phantom and Splunk plus sends out an alert email.

The playbook has been updated to work in conjunction with Recorded Future App for Phantom v2.0.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug("on_start() called")

    # call 'ip_intelligence_1' block
    ip_intelligence_1(container=container)

    return


"""
Match IP address against Recorded Future's Risk List for any IP addresses with a risk score of 90 or above.
"""


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
            ["ip_intelligence_1:action_result.data.*.risk.score", ">=", 90],
        ],
    )

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        add_bad_ip_to_list(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
        format_info(
            action=action,
            success=success,
            container=container,
            results=results,
            handle=handle,
        )
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

    results_data_1 = phantom.collect2(
        container=container,
        datapath=["ip_intelligence_1:action_result.parameter.ip"],
        action_results=results,
    )

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.add_list("Identified IP's", results_item_1_0)

    return


def format_info(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("format_info() called")

    template = """Destination={0}
Risk={1}
RiskString={2}
Rules={3}
Evidence={4}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.parameter.ip",
        "ip_intelligence_1:action_result.data.*.risk.score",
        "ip_intelligence_1:action_result.data.*.risk.riskSummary",
        "ip_intelligence_1:action_result.data.*.risk.evidenceDetails.*.rule",
        "ip_intelligence_1:action_result.data.*.risk.evidenceDetails.*.evidenceString",
    ]

    phantom.format(
        container=container,
        template=template,
        parameters=parameters,
        name="format_info",
    )

    post_data_1(container=container)

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

    template = """Alert from Recorded Futures App for Phantom - correlation playbook:

The IP address {0} with a risk score of {1} was added to the Bad IP List and sent back to Splunk.  

More information on this IOC can be found at  {2}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.parameter.ip",
        "ip_intelligence_1:action_result.data.*.risk.score",
        "ip_intelligence_1:action_result.data.*.intelCard",
    ]

    phantom.format(
        container=container,
        template=template,
        parameters=parameters,
        name="format_email",
    )

    send_email(container=container)

    return


"""


"""


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
            "to": "",
            "cc": "",
            "bcc": "",
            "headers": "",
            "subject": "Alert from Recorded Futures App for Phantom - correlation playbook",
        }
    )

    phantom.act("send email", parameters=parameters, assets=["smtp"], name="send_email")

    return


def ip_intelligence_1(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("ip_intelligence_1() called")

    # collect data for 'ip_intelligence_1' call
    container_data = phantom.collect2(
        container=container,
        datapath=["artifact:*.cef.destinationAddress", "artifact:*.id"],
    )

    parameters = []

    # build parameters list for 'ip_intelligence_1' call
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
        name="ip_intelligence_1",
    )

    return


def post_data_1(
    action=None,
    success=None,
    container=None,
    results=None,
    handle=None,
    filtered_artifacts=None,
    filtered_results=None,
):
    phantom.debug("post_data_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    # collect data for 'post_data_1' call
    formatted_data_1 = phantom.get_format_data(name="format_info")

    parameters = []

    # build parameters list for 'post_data_1' call
    parameters.append(
        {
            "index": "",
            "host": "localhost",
            "data": formatted_data_1,
            "source": "Phantom",
            "source_type": "Automation/Orchestration Platform",
        }
    )

    phantom.act(
        "post data", parameters=parameters, assets=["splunk"], name="post_data_1"
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
