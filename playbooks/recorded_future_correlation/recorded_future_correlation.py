"""
This playbook is called from a correlation search in Splunk ES
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Recorded_Future_Destination_IP' block
    Recorded_Future_Destination_IP(container=container)

    return

def Recorded_Future_Destination_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Recorded_Future_Destination_IP() called')

    # collect data for 'Recorded_Future_Destination_IP' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Recorded_Future_Destination_IP' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['recorded future'], callback=IOCs_90_Plus, name="Recorded_Future_Destination_IP")

    return

def IOCs_90_Plus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('IOCs_90_Plus() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Recorded_Future_Destination_IP:action_result.data.*.risk.score", ">=", 90],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Add_Bad_IP_to_List(action=action, success=success, container=container, results=results, handle=handle)
        Format_Data_For_Splunk(action=action, success=success, container=container, results=results, handle=handle)
        Format_Data_for_Email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def Add_Bad_IP_to_List(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Add_Bad_IP_to_List() called')

    results_data_1 = phantom.collect2(container=container, datapath=['Recorded_Future_Destination_IP:action_result.parameter.ip'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.add_list("Identified IP's", results_item_1_0)

    return

def Format_Data_For_Splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_Data_For_Splunk() called')
    
    template = """Destination={0}
Risk={1}
RiskString={2}
Rules={3}
Evidence={4}"""

    # parameter list for template variable replacement
    parameters = [
        "Recorded_Future_Destination_IP:action_result.parameter.ip",
        "Recorded_Future_Destination_IP:action_result.data.*.risk.score",
        "Recorded_Future_Destination_IP:action_result.data.*.risk.riskSummary",
        "Recorded_Future_Destination_IP:action_result.data.*.risk.evidenceDetails.*.rule",
        "Recorded_Future_Destination_IP:action_result.data.*.risk.evidenceDetails.*.evidenceString",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Data_For_Splunk")

    Post_back_to_Splunk_SOAR_info(container=container)

    return

def Format_Data_for_Email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_Data_for_Email() called')
    
    template = """The IP address {0} with a risk score of {1} was added to the Bad IP List and sent back to Splunk.  More information on this IOC can be found at  {2}"""

    # parameter list for template variable replacement
    parameters = [
        "Recorded_Future_Destination_IP:action_result.parameter.ip",
        "Recorded_Future_Destination_IP:action_result.data.*.risk.score",
        "Recorded_Future_Destination_IP:action_result.data.*.intelCard",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Data_for_Email")

    Email_notification(container=container)

    return

def Email_notification(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Email_notification() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Email_notification' call
    formatted_data_1 = phantom.get_format_data(name='Format_Data_for_Email')

    parameters = []
    
    # build parameters list for 'Email_notification' call
    parameters.append({
        'body': formatted_data_1,
        'from': "sender@example.com",
        'attachments': "",
        'to': "recipient@example.com",
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': "Alert Generated IP added to list",
    })

    phantom.act("send email", parameters=parameters, assets=['defaultmail'], name="Email_notification")

    return

def Post_back_to_Splunk_SOAR_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Post_back_to_Splunk_SOAR_info() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Post_back_to_Splunk_SOAR_info' call
    formatted_data_1 = phantom.get_format_data(name='Format_Data_For_Splunk')

    parameters = []
    
    # build parameters list for 'Post_back_to_Splunk_SOAR_info' call
    parameters.append({
        'index': "",
        'host': "",
        'data': formatted_data_1,
        'source': "Phantom",
        'source_type': "Automation/Orchestration Platform",
    })

    phantom.act("post data", parameters=parameters, assets=['splunk.example.com'], name="Post_back_to_Splunk_SOAR_info")

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