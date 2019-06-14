"""
This playbook searches through Splunk logs for entities that have been found by Recorded Future to be related to an IP address with a high risk score. The playbook should be spawned manually or through high fidelity correlation searches.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'ip_reputation_1' block
    ip_reputation_1(container=container)

    return

"""
Filter IPs with a risk score of 90 and above
"""
def filter_for_risk_score_above_90(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_for_risk_score_above_90() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.data.*.risk.score", "<", 90],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        return

    # call connected blocks for 'else' condition 2
    ip_intelligence_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def query_for_related_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('query_for_related_ips() called')
    
    template = """| makeresults | eval IP=\"{0}\" | makemv IP delim=\", \" | mvexpand IP | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntip.csv"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Entity_Type_Filter:condition_3:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "filtered-data:Entity_Type_Filter:condition_3:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="query_for_related_ips")

    format_list_of_ip(container=container)

    return

def format_list_of_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_list_of_ip() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'format_list_of_ip' call
    formatted_data_1 = phantom.get_format_data(name='query_for_related_ips')

    parameters = []
    
    # build parameters list for 'format_list_of_ip' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_ips, name="format_list_of_ip")

    return

def search_splunk_for_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('search_splunk_for_ips() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_splunk_for_ips' call

    parameters = []
    
    # build parameters list for 'search_splunk_for_ips' call
    parameters.append({
        'query': "sourcetype=pan:t* ((earliest=-1d latest=now)) |eval IP=dest_ip | lookup huntip.csv IP OUTPUT RC | search RC>10",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_ips_callback, name="search_splunk_for_ips", parent_action=action)

    return

def search_splunk_for_ips_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('search_splunk_for_ips_callback() called')
    
    format_ip(action=action, success=success, container=container, results=results, handle=handle)
    join_Send_email_if_related_entities_are_found(action=action, success=success, container=container, results=results, handle=handle)

    return

def format_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_ip() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "search_splunk_for_ips:action_result.data.*.IP",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip")

    Prompt_to_ask_user_to_add_to_Block_List(container=container)

    return

def Prompt_to_ask_user_to_add_to_Block_List(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Prompt_to_ask_user_to_add_to_Block_List() called')
    
    # set user and message variables for phantom.prompt call
    user = "rich"
    message = """Do you want to add these IP's to the block IP block list:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "search_splunk_for_ips:action_result.data.*.IP",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Prompt_to_ask_user_to_add_to_Block_List", parameters=parameters, response_types=response_types, callback=If_yes_add_to_list_if_no_drop)

    return

def If_yes_add_to_list_if_no_drop(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('If_yes_add_to_list_if_no_drop() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_to_ask_user_to_add_to_Block_List:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        add_ip_to_block_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def add_ip_to_block_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_ip_to_block_list() called')

    formatted_data_1 = phantom.get_format_data(name='format_ip')

    phantom.add_list("IP Block List", formatted_data_1)

    return

def Send_email_if_related_entities_are_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Send_email_if_related_entities_are_found() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["search_splunk_for_ips:action_result.data.*.IP", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        format_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["search_splunk_for_domains:action_result.data.*.domain", ">", 0],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        format_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["search_splunk_for_files:action_result.data.*.hash", ">", 0],
        ])

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        format_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["search_splunk_for_vulns:action_result.data.*.vuln", ">", 0],
        ])

    # call connected blocks if condition 4 matched
    if matched_artifacts_4 or matched_results_4:
        format_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 5

    return

def join_Send_email_if_related_entities_are_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Send_email_if_related_entities_are_found() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'search_splunk_for_ips', 'search_splunk_for_domains', 'search_splunk_for_files', 'search_splunk_for_vulns' ]):
        
        # call connected block "Send_email_if_related_entities_are_found"
        Send_email_if_related_entities_are_found(container=container, handle=handle)
    
    return

def format_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_email() called')
    
    template = """The very malicious destination IP {0} with a Risk Score of {1} was identified. 

Additional searches performed against logs showed that the following related entities occurring in > 10  relations have been found in the last 14 days.

IPs: {2}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.parameter.ip",
        "ip_intelligence_1:action_result.data.*.risk.score",
        "search_splunk_for_ips:action_result.data.*.IP",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_email")

    send_email_1(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_email')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'from': "sender@example.com",
        'attachments': "",
        'headers': "",
        'cc': "",
        'bcc': "",
        'to': "recipient@example.com",
        'subject': "Malicous IP with related entities found in Splunk",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

    return

def query_for_related_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('query_for_related_domains() called')
    
    template = """| makeresults | eval domain=\"{0}\" | makemv domain delim=\", \" | mvexpand domain | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntdomain.csv"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Entity_Type_Filter:condition_4:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "filtered-data:Entity_Type_Filter:condition_4:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="query_for_related_domains")

    format_list_of_domains(container=container)

    return

def format_list_of_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_list_of_domains() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'format_list_of_domains' call
    formatted_data_1 = phantom.get_format_data(name='query_for_related_domains')

    parameters = []
    
    # build parameters list for 'format_list_of_domains' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_domains, name="format_list_of_domains")

    return

def query_for_related_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('query_for_related_files() called')
    
    template = """| makeresults | eval hash=\"{0}\" | makemv hash delim=\", \" | mvexpand hash | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup hunthash.csv"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Entity_Type_Filter:condition_1:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "filtered-data:Entity_Type_Filter:condition_1:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="query_for_related_files")

    format_list_of_file_hashes(container=container)

    return

def format_list_of_file_hashes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_list_of_file_hashes() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'format_list_of_file_hashes' call
    formatted_data_1 = phantom.get_format_data(name='query_for_related_files')

    parameters = []
    
    # build parameters list for 'format_list_of_file_hashes' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_files, name="format_list_of_file_hashes")

    return

def query_for_related_vulns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('query_for_related_vulns() called')
    
    template = """| makeresults | eval vuln=\"{0}\" | makemv vuln delim=\", \" | mvexpand vuln | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntvuln.csv"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Entity_Type_Filter:condition_2:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "filtered-data:Entity_Type_Filter:condition_2:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="query_for_related_vulns")

    format_list_of_vulns(container=container)

    return

def format_list_of_vulns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_list_of_vulns() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'format_list_of_vulns' call
    formatted_data_1 = phantom.get_format_data(name='query_for_related_vulns')

    parameters = []
    
    # build parameters list for 'format_list_of_vulns' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_vulns, name="format_list_of_vulns")

    return

def search_splunk_for_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('search_splunk_for_domains() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_splunk_for_domains' call

    parameters = []
    
    # build parameters list for 'search_splunk_for_domains' call
    parameters.append({
        'query': "sourcetype=pan:threat ((earliest=-1d latest=now)) |eval domain=dest_hostname | lookup huntdomain.csv domain OUTPUT RC | search RC>10",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=join_Send_email_if_related_entities_are_found, name="search_splunk_for_domains", parent_action=action)

    return

def search_splunk_for_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('search_splunk_for_files() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_splunk_for_files' call

    parameters = []
    
    # build parameters list for 'search_splunk_for_files' call
    parameters.append({
        'query': "index=main sourcetype=symantec:ep:risk:file ((earliest=-1d latest=now)) |eval hash=file_hash | lookup hunthash.csv hash OUTPUT RC | search RC>10",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=join_Send_email_if_related_entities_are_found, name="search_splunk_for_files", parent_action=action)

    return

def search_splunk_for_vulns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('search_splunk_for_vulns() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_splunk_for_vulns' call

    parameters = []
    
    # build parameters list for 'search_splunk_for_vulns' call
    parameters.append({
        'query': "index=main sourcetype=\"tenable:sc:vuln\" ((earliest=-7d latest=now)) |eval vuln=cve | lookup huntvuln.csv vuln OUTPUT RC | search RC>10",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk'], callback=join_Send_email_if_related_entities_are_found, name="search_splunk_for_vulns", parent_action=action)

    return

def ip_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_intelligence_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_intelligence_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_intelligence_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("ip intelligence", parameters=parameters, assets=['recorded-future'], callback=Entity_Type_Filter, name="ip_intelligence_1")

    return

"""
Filter on Entity Type
"""
def Entity_Type_Filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Entity_Type_Filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.type", "==", "Hash"],
        ],
        name="Entity_Type_Filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        query_for_related_files(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.type", "==", "CyberVulnerability"],
        ],
        name="Entity_Type_Filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        query_for_related_vulns(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.type", "==", "IpAddress"],
        ],
        name="Entity_Type_Filter:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        query_for_related_ips(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.type", "==", "InternetDomainName"],
        ],
        name="Entity_Type_Filter:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        query_for_related_domains(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return

"""
Quick IP reputation to get the Risk Score
"""
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

    phantom.act("ip reputation", parameters=parameters, assets=['recorded-future'], callback=filter_for_risk_score_above_90, name="ip_reputation_1")

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