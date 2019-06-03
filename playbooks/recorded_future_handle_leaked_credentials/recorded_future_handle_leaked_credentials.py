"""
This playbook was created to show how to retrieve Alerts from Recorded Future for processing within the Phantom platform. A typical usecase is handling of leaked credentials.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'alert_data_lookup_3' block
    alert_data_lookup_3(container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """Recorded Future is alerting on probable leaked credentials.

Alert: 
  {0}

More information: 
  {1}

Leaked Email adresses:
  {2}"""

    # parameter list for template variable replacement
    parameters = [
        "alert_data_lookup_3:action_result.data.*.alerts.*.alert.content.title",
        "alert_data_lookup_3:action_result.data.*.alerts.*.alert.content.url",
        "alert_data_lookup_3:action_result.data.*.alerts.*.alert.entities.EmailAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_1(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'from': "phantom@example.com",
        'attachments': "",
        'to': "security@example.com",
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': "Recorded Future Alert about Leaked Credentials",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

    return

def alert_data_lookup_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('alert_data_lookup_3() called')

    # collect data for 'alert_data_lookup_3' call

    parameters = []
    
    # build parameters list for 'alert_data_lookup_3' call
    parameters.append({
        'rule_id': "",
        'timeframe': "-24h to now",
    })

    phantom.act("alert data lookup", parameters=parameters, assets=['recordedfuture'], callback=format_1, name="alert_data_lookup_3")

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