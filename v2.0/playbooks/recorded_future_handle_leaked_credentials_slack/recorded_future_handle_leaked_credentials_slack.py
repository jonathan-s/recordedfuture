"""
This playbook was created to show how to retrieve Alerts from Recorded Future for processing within the Phantom platform. A typical usecase is handling of leaked credentials.

The playbook has been updated to work in conjunction with Recorded Future App for Phantom v2.0.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'alert_data_lookup_3' block
    alert_data_lookup_3(container=container)

    return

def format_slack_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_slack_message() called')
    
    template = """*Alert from Recorded Futures App for Phantom - leaked credentials playbook:*

>Alert rule that has been triggered:  *{0}*
>
>Total number of Alerts:  *{1}*
>
>For further information:  {2}"""

    # parameter list for template variable replacement
    parameters = [
        "alert_data_lookup_3:action_result.data.*.rule.name",
        "alert_data_lookup_3:action_result.summary.total_number_of_alerts",
        "alert_data_lookup_3:action_result.data.*.rule.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_slack_message")

    send_message_1(container=container)

    return

def alert_data_lookup_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('alert_data_lookup_3() called')

    # collect data for 'alert_data_lookup_3' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.cs1', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'alert_data_lookup_3' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'rule_id': container_item[0],
                'timeframe': "anytime",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("alert data lookup", parameters=parameters, assets=['recorded-future'], callback=format_slack_message, name="alert_data_lookup_3")

    return

def send_message_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_message_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_message_1' call
    formatted_data_1 = phantom.get_format_data(name='format_slack_message')

    parameters = []
    
    # build parameters list for 'send_message_1' call
    parameters.append({
        'message': formatted_data_1,
        'destination': "# phantom-demo",
    })

    phantom.act("send message", parameters=parameters, assets=['slack'], name="send_message_1")

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