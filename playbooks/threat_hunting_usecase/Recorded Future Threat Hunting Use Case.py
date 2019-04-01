"""
This use can be spawned manually or through high fidelity correlation searches.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Recorded_Future_IOC_Lookup' block
    Recorded_Future_IOC_Lookup(container=container)

    return

def Recorded_Future_IOC_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Recorded_Future_IOC_Lookup() called')

    # collect data for 'Recorded_Future_IOC_Lookup' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Recorded_Future_IOC_Lookup' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['recorded future'], callback=Process_Risk_90_Plus, name="Recorded_Future_IOC_Lookup")

    return

def Process_Risk_90_Plus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Process_Risk_90_Plus() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Recorded_Future_IOC_Lookup:action_result.data.*.risk.score", ">=", 90],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        SPL_Query_to_build_IP_Lookup(action=action, success=success, container=container, results=results, handle=handle)
        SPL_Query_to_build_Domain_Lookup(action=action, success=success, container=container, results=results, handle=handle)
        SPL_Query_to_build_Hash_List(action=action, success=success, container=container, results=results, handle=handle)
        SPL_Query_to_build_related_vulns(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def SPL_Query_to_build_IP_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('SPL_Query_to_build_IP_Lookup() called')
    
    template = """| makeresults | eval IP=\"{0}\" | makemv IP delim=\", \" | mvexpand IP | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntip.csv"""

    # parameter list for template variable replacement
    parameters = [
        "Recorded_Future_IOC_Lookup:action_result.data.*.relatedEntities.RelatedIpAddress.*.name",
        "Recorded_Future_IOC_Lookup:action_result.data.*.relatedEntities.RelatedIpAddress.*.refCount",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SPL_Query_to_build_IP_Lookup")

    Build_IP_Lookup_Table(container=container)

    return

def Build_IP_Lookup_Table(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Build_IP_Lookup_Table() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Build_IP_Lookup_Table' call
    formatted_data_1 = phantom.get_format_data(name='SPL_Query_to_build_IP_Lookup')

    parameters = []
    
    # build parameters list for 'Build_IP_Lookup_Table' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk-ps.recfut.com'], callback=Search_against_last_1_day_of_IP_Traffic, name="Build_IP_Lookup_Table")

    return

def Search_against_last_1_day_of_IP_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Search_against_last_1_day_of_IP_Traffic() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Search_against_last_1_day_of_IP_Traffic' call

    parameters = []
    
    # build parameters list for 'Search_against_last_1_day_of_IP_Traffic' call
    parameters.append({
        'query': "sourcetype=pan:t* ((earliest=-1d latest=now)) |eval IP=dest_ip | lookup huntip.csv IP OUTPUT RC | search RC>10",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk-ps.recfut.com'], callback=Search_against_last_1_day_of_IP_Traffic_callback, name="Search_against_last_1_day_of_IP_Traffic", parent_action=action)

    return

def Search_against_last_1_day_of_IP_Traffic_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Search_against_last_1_day_of_IP_Traffic_callback() called')
    
    Format_IP_for_Blocklist(action=action, success=success, container=container, results=results, handle=handle)
    join_Send_email_if_related_entities_are_found(action=action, success=success, container=container, results=results, handle=handle)

    return

def Format_IP_for_Blocklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_IP_for_Blocklist() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "Search_against_last_1_day_of_IP_Traffic:action_result.data.*.IP",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_IP_for_Blocklist")

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
        "Search_against_last_1_day_of_IP_Traffic:action_result.data.*.IP",
    ]

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="Prompt_to_ask_user_to_add_to_Block_List", parameters=parameters, options=options, callback=If_yes_add_to_list_if_no_drop)

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
        Add_to_Block_IP_List(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def Add_to_Block_IP_List(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Add_to_Block_IP_List() called')

    formatted_data_1 = phantom.get_format_data(name='Format_IP_for_Blocklist')

    phantom.add_list("IP Block List", formatted_data_1)

    return

def Send_email_if_related_entities_are_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Send_email_if_related_entities_are_found() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Search_against_last_1_day_of_IP_Traffic:action_result.data.*.IP", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Format_Email_message(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Search_against_last_1_day_of_Domain_Logs:action_result.data.*.domain", ">", 0],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        Format_Email_message(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Search_against_last_1_day_of_Hash_Logs:action_result.data.*.hash", ">", 0],
        ])

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        Format_Email_message(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Search_against_last_7_days_of_Vuln_data:action_result.data.*.vuln", ">", 0],
        ])

    # call connected blocks if condition 4 matched
    if matched_artifacts_4 or matched_results_4:
        Format_Email_message(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 5

    return

def join_Send_email_if_related_entities_are_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Send_email_if_related_entities_are_found() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'Search_against_last_1_day_of_IP_Traffic', 'Search_against_last_1_day_of_Domain_Logs', 'Search_against_last_1_day_of_Hash_Logs', 'Search_against_last_7_days_of_Vuln_data' ]):
        
        # call connected block "Send_email_if_related_entities_are_found"
        Send_email_if_related_entities_are_found(container=container, handle=handle)
    
    return

def Format_Email_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_Email_message() called')
    
    template = """The very malicious destination IP {0} with a Risk Score of {1} was identified. 

Additional searches performed against logs showed that the following related entities occurring in > 10  relations have been found in the last 14 days.

IPs: {2}"""

    # parameter list for template variable replacement
    parameters = [
        "Recorded_Future_IOC_Lookup:action_result.parameter.ip",
        "Recorded_Future_IOC_Lookup:action_result.data.*.risk.score",
        "Search_against_last_1_day_of_IP_Traffic:action_result.data.*.IP",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Email_message")

    send_email_1(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='Format_Email_message')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'from': "phantom@recfut.com",
        'attachments': "",
        'to': "rich@recordedfuture.com",
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': "Malicous IP with related entities found in Splunk",
    })

    phantom.act("send email", parameters=parameters, assets=['defaultmail'], name="send_email_1")

    return

def SPL_Query_to_build_Domain_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('SPL_Query_to_build_Domain_Lookup() called')
    
    template = """| makeresults | eval domain=\"{0}\" | makemv domain delim=\", \" | mvexpand domain | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntdomain.csv"""

    # parameter list for template variable replacement
    parameters = [
        "Recorded_Future_IOC_Lookup:action_result.data.*.relatedEntities.RelatedInternetDomainName.*.name",
        "Recorded_Future_IOC_Lookup:action_result.data.*.relatedEntities.RelatedIpAddress.*.refCount",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SPL_Query_to_build_Domain_Lookup")

    Build_Domain_Lookup_Table(container=container)

    return

def Build_Domain_Lookup_Table(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Build_Domain_Lookup_Table() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Build_Domain_Lookup_Table' call
    formatted_data_1 = phantom.get_format_data(name='SPL_Query_to_build_Domain_Lookup')

    parameters = []
    
    # build parameters list for 'Build_Domain_Lookup_Table' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk-ps.recfut.com'], callback=Search_against_last_1_day_of_Domain_Logs, name="Build_Domain_Lookup_Table")

    return

def SPL_Query_to_build_Hash_List(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('SPL_Query_to_build_Hash_List() called')
    
    template = """| makeresults | eval hash=\"{0}\" | makemv hash delim=\", \" | mvexpand hash | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup hunthash.csv"""

    # parameter list for template variable replacement
    parameters = [
        "Recorded_Future_IOC_Lookup:action_result.data.*.relatedEntities.RelatedHash.*.name",
        "Recorded_Future_IOC_Lookup:action_result.data.*.relatedEntities.RelatedHash.*.refCount",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SPL_Query_to_build_Hash_List")

    Build_Hash_Lookup_Table(container=container)

    return

def Build_Hash_Lookup_Table(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Build_Hash_Lookup_Table() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Build_Hash_Lookup_Table' call
    formatted_data_1 = phantom.get_format_data(name='SPL_Query_to_build_Hash_List')

    parameters = []
    
    # build parameters list for 'Build_Hash_Lookup_Table' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk-ps.recfut.com'], callback=Search_against_last_1_day_of_Hash_Logs, name="Build_Hash_Lookup_Table")

    return

def SPL_Query_to_build_related_vulns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('SPL_Query_to_build_related_vulns() called')
    
    template = """| makeresults | eval vuln=\"{0}\" | makemv vuln delim=\", \" | mvexpand vuln | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntvuln.csv"""

    # parameter list for template variable replacement
    parameters = [
        "Recorded_Future_IOC_Lookup:action_result.data.*.relatedEntities.RelatedCyberVulnerability.*.name",
        "Recorded_Future_IOC_Lookup:action_result.data.*.relatedEntities.RelatedCyberVulnerability.*.refCount",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="SPL_Query_to_build_related_vulns")

    Build_Vulnerability_Lookup_Table(container=container)

    return

def Build_Vulnerability_Lookup_Table(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Build_Vulnerability_Lookup_Table() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Build_Vulnerability_Lookup_Table' call
    formatted_data_1 = phantom.get_format_data(name='SPL_Query_to_build_related_vulns')

    parameters = []
    
    # build parameters list for 'Build_Vulnerability_Lookup_Table' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk-ps.recfut.com'], callback=Search_against_last_7_days_of_Vuln_data, name="Build_Vulnerability_Lookup_Table")

    return

def Search_against_last_1_day_of_Domain_Logs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Search_against_last_1_day_of_Domain_Logs() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Search_against_last_1_day_of_Domain_Logs' call

    parameters = []
    
    # build parameters list for 'Search_against_last_1_day_of_Domain_Logs' call
    parameters.append({
        'query': "sourcetype=pan:threat ((earliest=-1d latest=now)) |eval domain=dest_hostname | lookup huntdomain.csv domain OUTPUT RC | search RC>10",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk-ps.recfut.com'], callback=join_Send_email_if_related_entities_are_found, name="Search_against_last_1_day_of_Domain_Logs", parent_action=action)

    return

def Search_against_last_1_day_of_Hash_Logs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Search_against_last_1_day_of_Hash_Logs() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Search_against_last_1_day_of_Hash_Logs' call

    parameters = []
    
    # build parameters list for 'Search_against_last_1_day_of_Hash_Logs' call
    parameters.append({
        'query': "index=main sourcetype=symantec:ep:risk:file ((earliest=-1d latest=now)) |eval hash=file_hash | lookup hunthash.csv hash OUTPUT RC | search RC>10",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk-ps.recfut.com'], callback=join_Send_email_if_related_entities_are_found, name="Search_against_last_1_day_of_Hash_Logs", parent_action=action)

    return

def Search_against_last_7_days_of_Vuln_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Search_against_last_7_days_of_Vuln_data() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Search_against_last_7_days_of_Vuln_data' call

    parameters = []
    
    # build parameters list for 'Search_against_last_7_days_of_Vuln_data' call
    parameters.append({
        'query': "index=main sourcetype=\"tenable:sc:vuln\" ((earliest=-7d latest=now)) |eval vuln=cve | lookup huntvuln.csv vuln OUTPUT RC | search RC>10",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk-ps.recfut.com'], callback=join_Send_email_if_related_entities_are_found, name="Search_against_last_7_days_of_Vuln_data", parent_action=action)

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