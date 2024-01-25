"""
This playbook was created to show how to retrieve Alerts from Recorded Future for processing within the Phantom platform. A typical usecase is handling of leaked credentials.\n\nThe playbook has been updated to work in conjunction with Recorded Future App for Phantom v3.1.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug("on_start() called")

    # call 'get_alerts' block
    get_alerts(container=container)

    return


def get_alerts(
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
    phantom.debug("get_alerts() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(
        container=container, datapath=["artifact:*.cef.cs1", "artifact:*.id"]
    )

    parameters = []

    # build parameters list for 'get_alerts' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append(
                {
                    "rule_id": container_artifact_item[0],
                    "timeframe": "-24h to now",
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
        "alert data lookup",
        parameters=parameters,
        name="get_alerts",
        assets=["recorded-future"],
        callback=format_slack_message,
    )

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

    template = """*Alert from Recorded Futures App for Phantom - leaked credentials playbook:*\n\n>Alert rule that has been triggered:  *{0}*\n>\n>Total number of Alerts:  *{1}*\n>\n>For further information:  {2}\n"""

    # parameter list for template variable replacement
    parameters = [
        "get_alerts:action_result.data.*.alerts.*.alert.content.rule.name",
        "get_alerts:action_result.summary.total_number_of_alerts",
        "get_alerts:action_result.data.*.rule.url",
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
    )

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
