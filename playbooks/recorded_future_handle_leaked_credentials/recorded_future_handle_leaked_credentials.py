"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'alert_data_lookup_1' block
    alert_data_lookup_1(container=container)

    return

def alert_data_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('alert_data_lookup_1() called')

    # collect data for 'alert_data_lookup_1' call

    parameters = []
    
    # build parameters list for 'alert_data_lookup_1' call
    parameters.append({
        'rule_id': "VNPVFc",
        'timeframe': "-24h to now",
    })

    phantom.act("alert data lookup", parameters=parameters, assets=['recordedfuture2'], callback=format_1, name="alert_data_lookup_1")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """Recorded Future is alerting on probable leaked credentials.

Alert: {1}
More information: {2}

Leaked Email adresses:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "alert_data_lookup_1:action_result.data.*.alert.entities.EmailAddress.*",
        "alert_data_lookup_1:action_result.data.*.alert.alertTitle",
        "alert_data_lookup_1:action_result.data.*.alert.alertUrl",
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
        'from': "phantom@example.com",
        'to': "security@example.com",
        'cc': "",
        'bcc': "",
        'subject': "Recorded Future Alert about Leaked Credentials",
        'body': formatted_data_1,
        'attachments': "",
        'headers': "",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

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