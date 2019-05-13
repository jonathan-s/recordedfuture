"""
Show's enrichment with decision based off Risk Score.  This playbook is typically used for artifact enrichment.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'ip_reputation_1' block
    ip_reputation_1(container=container)

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['recordedfuture'], callback=Filter_For_Risk_90_Plus, name="ip_reputation_1")

    return

def Filter_For_Risk_90_Plus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Filter_For_Risk_90_Plus() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.data.*.risk.score", ">=", 90],
            ["ip_reputation_1:action_result.data.*.risk.evidenceDetails.*.rule", "in", "Current C&C Server"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Format_High_Threat_Email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def Send_Very_Malicious_IP_Email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Send_Very_Malicious_IP_Email() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Send_Very_Malicious_IP_Email' call
    formatted_data_1 = phantom.get_format_data(name='Format_High_Threat_Email')

    parameters = []
    
    # build parameters list for 'Send_Very_Malicious_IP_Email' call
    parameters.append({
        'body': formatted_data_1,
        'from': "sender@example.com",
        'attachments': "",
        'headers': "",
        'bcc': "",
        'to': "recipient@example.com",
        'subject': "Very Malicious IP ",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=Add_to_Bad_IP_List, name="Send_Very_Malicious_IP_Email")

    return

def Format_High_Threat_Email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_High_Threat_Email() called')
    
    template = """The IP {0}  is has a risk score of {1} 

The rules triggered for this IP are:

{3}

{4}

The Evidence Details are:

{2}

Related Entities:

{6}

{7}

{8}

More information about:
{5}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation_1:action_result.parameter.ip",
        "ip_reputation_1:action_result.data.*.risk.score",
        "ip_reputation_1:action_result.data.*.risk.evidenceDetails.*.evidenceString",
        "ip_reputation_1:action_result.data.*.risk.riskSummary",
        "ip_reputation_1:action_result.data.*.risk.evidenceDetails.*.rule",
        "ip_reputation_1:action_result.data.*.intelCard",
        "ip_reputation_1:action_result.data.*.relatedEntities.*.type",
        "ip_reputation_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "ip_reputation_1:action_result.data.*.relatedEntities.*.entities.*.entity.type",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_High_Threat_Email")

    Send_Very_Malicious_IP_Email(container=container)

    return

def Add_to_Bad_IP_List(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Add_to_Bad_IP_List() called')

    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    container_item_0 = [item[0] for item in container_data]

    phantom.add_list("Identified IP's", container_item_0)

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