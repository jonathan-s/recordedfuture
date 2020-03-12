"""
Starting with a single IP address, this playbook gathers a list of related IP addresses, domain names, file hashes, and vulnerability CVE's from Recorded Future. Then Splunk is used to build threat hunting lookup tables and search across multiple data sources for events containing the related entities. Finally, IP addresses are blocked if approved by an analyst and an email is sent to notify a responder if more than 10 of a certain kind of entity are matched at once.
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
Proceed if the risk score is higher than a certain threshold
"""
def risk_score_threshold(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('risk_score_threshold() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.data.*.riskscore", ">=", 90],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        ip_intelligence_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

"""
Build a Splunk query that looks for netscreen:firewall events where any of the Related IPs occur in the dest field.
"""
def ip_search_string(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_search_string() called')
    
    template = """index=* sourcetype=\"netscreen:firewall\" dest IN ({0})"""

    # parameter list for template variable replacement
    parameters = [
        "extract_ip_addresses:custom_function:relatedList",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ip_search_string")

    splunksearch_for_ip(container=container)

    return

"""
Search Netscreen firewall logs for any events with threat-related ip addresses in the dest field.
"""
def splunksearch_for_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('splunksearch_for_ip() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'splunksearch_for_ip' call
    formatted_data_1 = phantom.get_format_data(name='ip_search_string')

    parameters = []
    
    # build parameters list for 'splunksearch_for_ip' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk','splunk'], callback=splunksearch_for_ip_callback, name="splunksearch_for_ip")

    return

def splunksearch_for_ip_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('splunksearch_for_ip_callback() called')
    
    only_if_results(action=action, success=success, container=container, results=results, handle=handle)
    join_check_for_results(action=action, success=success, container=container, results=results, handle=handle)

    return

"""
Ask an analyst whether the discovered related IP addresses should be blocked
"""
def recorded_future_threat_hunting_block_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('recorded_future_threat_hunting_block_ip() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Do you want to add the following IP(s) to the block IP block list:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "splunksearch_for_ip:action_result.data.*.dest",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="recorded_future_threat_hunting_block_ip", parameters=parameters, response_types=response_types, callback=check_prompt)

    return

"""
Only proceed if the analyst approved the prompt
"""
def check_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('check_prompt() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["recorded_future_threat_hunting_block_ip:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        add_ip_to_block_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

"""
Add the IP address to a Phantom custom list, which can be tracked as a REST-accessible external block list by a firewall
"""
def add_ip_to_block_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_ip_to_block_list() called')

    results_data_1 = phantom.collect2(container=container, datapath=['splunksearch_for_ip:action_result.data.*.IP'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.add_list("IP Block List", results_item_1_0)

    return

"""
Search ISC Bind logs for any events with threat-related domain names in the query field.
"""
def spunksearch_for_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('spunksearch_for_domains() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'spunksearch_for_domains' call
    formatted_data_1 = phantom.get_format_data(name='domain_search_string')

    parameters = []
    
    # build parameters list for 'spunksearch_for_domains' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk','splunk'], callback=join_check_for_results, name="spunksearch_for_domains")

    return

"""
Search Symantec Endpoint Protection logs for sightings of threat-related file hashes.
"""
def splunksearch_for_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('splunksearch_for_files() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'splunksearch_for_files' call
    formatted_data_1 = phantom.get_format_data(name='file_hash_search_string')

    parameters = []
    
    # build parameters list for 'splunksearch_for_files' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk','splunk'], callback=join_check_for_results, name="splunksearch_for_files")

    return

"""
Search Tenable vulnerability scanning logs for any vulnerabilities related to the initial IP addresses.
"""
def spunksearch_for_vulns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('spunksearch_for_vulns() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'spunksearch_for_vulns' call
    formatted_data_1 = phantom.get_format_data(name='vulnerability_search_string')

    parameters = []
    
    # build parameters list for 'spunksearch_for_vulns' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunk','splunk'], callback=join_check_for_results, name="spunksearch_for_vulns")

    return

"""
Query for the full context about the IP address and related entities from Recorded Future
"""
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

    phantom.act("ip intelligence", parameters=parameters, assets=['recorded-future '], callback=ip_intelligence_1_callback, name="ip_intelligence_1")

    return

def ip_intelligence_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_intelligence_1_callback() called')
    
    extract_ip_addresses(action=action, success=success, container=container, results=results, handle=handle)
    extract_domains(action=action, success=success, container=container, results=results, handle=handle)
    extract_vulnerabilities(action=action, success=success, container=container, results=results, handle=handle)
    extract_file_hashes(action=action, success=success, container=container, results=results, handle=handle)

    return

"""
Query for the risk score from Recorded Future
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

    phantom.act("ip reputation", parameters=parameters, assets=['recorded-future '], callback=risk_score_threshold, name="ip_reputation_1")

    return

"""
Filter based on type of related entity and the number of recent references in Recorded Future data. 
"""
def extract_ip_addresses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('extract_ip_addresses() called')
    input_parameter_0 = "RelatedIpAddress"
    input_parameter_1 = 10
    results_data_1 = phantom.collect2(container=container, datapath=['ip_intelligence_1:action_result.data.*.relatedEntities'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    extract_ip_addresses__relatedList = None
    extract_ip_addresses__resultCount = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('Filter_on_RelatedIpAddress_and_Count(0): %s' % results_data_1)
    phantom.debug('Filter_on_RelatedIpAddress_and_Count(1): %s' % input_parameter_0)
    phantom.debug('Filter_on_RelatedIpAddress_and_Count(2): %s' % input_parameter_1)
    extract_ip_addresses__resultCount = 0
    tmplist = [line for line in results_data_1[0][0] if line['type'] == input_parameter_0]
    if tmplist:
        tmplist2 = [[ren['entity']['name'] for ren in line['entities']
                                                          if ren['count'] >= input_parameter_1]
                                                         for line in tmplist]
        if tmplist2:
            extract_ip_addresses__relatedList = tmplist2[0]
        extract_ip_addresses__resultCount = len(extract_ip_addresses__relatedList)
    phantom.debug('Filter_on_RelatedIpAddress_and_Count relatedList: %s' % extract_ip_addresses__relatedList)
    phantom.debug('Filter_on_RelatedIpAddress_and_Count resultCount: %d' % extract_ip_addresses__resultCount)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='extract_ip_addresses:relatedList', value=json.dumps(extract_ip_addresses__relatedList))
    phantom.save_run_data(key='extract_ip_addresses:resultCount', value=json.dumps(extract_ip_addresses__resultCount))
    ip_search_string(container=container)

    return

"""
Filter based on type of related entity and the number of recent references in Recorded Future data. 
"""
def extract_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('extract_domains() called')
    input_parameter_0 = "RelatedDomainAddress"
    input_parameter_1 = 10
    results_data_1 = phantom.collect2(container=container, datapath=['ip_intelligence_1:action_result.data.*.relatedEntities'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    extract_domains__RelatedList = None
    extract_domains__ResultCount = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('Filter_on_RelatedDomain_and_count() parameter: %s' % results_data_1)
    tmplist = [line for line in results_data_1[0][0] if line['type'] == input_parameter_0]
    extract_domains__ResultCount = 0
    if tmplist:
        tmplist2 = [[ren['entity']['name'] for ren in line['entities']
                     if ren['count'] >= input_parameter_1]
                    for line in tmplist]
        if tmplist2:
            extract_domains__RelatedList = tmplist2[0]
            extract_domains__ResultCount = len(extract_domains__RelatedList)
    phantom.debug('Filter_on_RelatedDomain_and_count RelatedList: %s' % extract_domains__RelatedList)
    phantom.debug('Filter_on_RelatedDomain_and_count ResultCount: %d' % extract_domains__ResultCount)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='extract_domains:RelatedList', value=json.dumps(extract_domains__RelatedList))
    phantom.save_run_data(key='extract_domains:ResultCount', value=json.dumps(extract_domains__ResultCount))
    domain_search_string(container=container)

    return

"""
Build a Splunk query that looks for isc:bind:query events where any of the Related Domains occur in the query field.
"""
def domain_search_string(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_search_string() called')
    
    template = """index=* sourcetype=\"isc:bind:query\" query IN ({0})"""

    # parameter list for template variable replacement
    parameters = [
        "extract_domains:custom_function:RelatedList",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="domain_search_string")

    spunksearch_for_domains(container=container)

    return

"""
Filter based on type of related entity and the number of recent references in Recorded Future data. 
"""
def extract_vulnerabilities(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('extract_vulnerabilities() called')
    input_parameter_0 = "RelatedVulnerabilities"
    input_parameter_1 = "2"
    results_data_1 = phantom.collect2(container=container, datapath=['ip_intelligence_1:action_result.data.*.relatedEntities'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    extract_vulnerabilities__relatedList = None
    extract_vulnerabilities__resultCount = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('Filter_RelatedVulns_and_count() parameter: %s' % results_data_1)
    extract_vulnerabilities__resultCount = 0
    tmplist = [line for line in results_data_1[0][0] if line['type'] == input_parameter_0]
    if tmplist:
        tmplist2 = [[ren['entity']['name'] for ren in line['entities']
                                                     if ren['count'] >= input_parameter_1]
                                                     for line in tmplist]
        if tmplist2:
            extract_vulnerabilities__relatedList = tmplist2[0]
            extract_vulnerabilities__resultCount = len(extract_vulnerabilities__relatedList)
    phantom.debug('Filter_RelatedVulns_and_count relatedList: %s' % extract_vulnerabilities__relatedList)
    phantom.debug('Filter_RelatedVulns_and_count resultCount: %d' % extract_vulnerabilities__resultCount)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='extract_vulnerabilities:relatedList', value=json.dumps(extract_vulnerabilities__relatedList))
    phantom.save_run_data(key='extract_vulnerabilities:resultCount', value=json.dumps(extract_vulnerabilities__resultCount))
    vulnerability_search_string(container=container)

    return

"""
Build a Splunk query that looks for tenable:sc:vuln events where any of the Related Vulnerabilities occur in the cve field.
"""
def vulnerability_search_string(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('vulnerability_search_string() called')
    
    template = """index=* sourcetype=\"tenable:sc:vuln\" cve IN ({0})"""

    # parameter list for template variable replacement
    parameters = [
        "extract_vulnerabilities:custom_function:relatedList",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="vulnerability_search_string")

    spunksearch_for_vulns(container=container)

    return

"""
Filter based on type of related entity and the number of recent references in Recorded Future data. 
"""
def extract_file_hashes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('extract_file_hashes() called')
    input_parameter_0 = "RelatedHash"
    input_parameter_1 = 10
    results_data_1 = phantom.collect2(container=container, datapath=['ip_intelligence_1:action_result.data.*.relatedEntities'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    extract_file_hashes__relatedList = None
    extract_file_hashes__resultCount = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('Filter_on_RelatedHash_and_count() parameter: %s' % results_data_1)
    extract_file_hashes__resultCount = 0
    tmplist = [line for line in results_data_1[0][0] if line['type'] == input_parameter_0]
    if tmplist:
        tmplist2 = [[ren['entity']['name'] for ren in line['entities']
                                                              if ren['count'] >= input_parameter_1]
                                                             for line in tmplist]
        if tmplist2:
            extract_file_hashes__relatedList = tmplist2[0]
            extract_file_hashes__resultCount = len(extract_file_hashes__relatedList)
    phantom.debug('Filter_on_RelatedHash_and_count relatedList: %s' % extract_file_hashes__relatedList)
    phantom.debug('Filter_on_RelatedHash_and_count resultCount: %d' % extract_file_hashes__resultCount)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='extract_file_hashes:relatedList', value=json.dumps(extract_file_hashes__relatedList))
    phantom.save_run_data(key='extract_file_hashes:resultCount', value=json.dumps(extract_file_hashes__resultCount))
    file_hash_search_string(container=container)

    return

"""
Build a Splunk query that looks for symantec:ep:risk:file events where any of the Related File Hashes occur in the Application_Hash field.
"""
def file_hash_search_string(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_hash_search_string() called')
    
    template = """index=* sourcetype=\"symantec:ep:risk:file\" Application_Hash IN ({0})"""

    # parameter list for template variable replacement
    parameters = [
        "extract_file_hashes:custom_function:relatedList",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="file_hash_search_string")

    splunksearch_for_files(container=container)

    return

"""
Add a comment that no Related Entities were found.
"""
def no_related_entities_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('no_related_entities_comment() called')

    phantom.comment(container=container, comment="Searches for Related Entities yielded no results.")

    return

"""
Check that at least one of the Related Entities categories found matches in the logs.
"""
def check_for_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('check_for_results() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["splunksearch_for_ip:action_result.summary.total_events", ">", 0],
            ["spunksearch_for_domains:action_result.summary.total_events", ">", 0],
            ["splunksearch_for_files:action_result.summary.total_events", ">", 0],
            ["spunksearch_for_vulns:action_result.summary.total_events", ">", 0],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        slack_notification(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    no_related_entities_comment(action=action, success=success, container=container, results=results, handle=handle)

    return

def join_check_for_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_check_for_results() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'spunksearch_for_domains', 'splunksearch_for_files', 'spunksearch_for_vulns', 'splunksearch_for_ip' ]):
        
        # call connected block "check_for_results"
        check_for_results(container=container, handle=handle)
    
    return

"""
Only proceed if there are related IPs found.
"""
def only_if_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('only_if_results() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["splunksearch_for_ip:action_result.data.*.dest", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        recorded_future_threat_hunting_block_ip(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def slack_notification(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('slack_notification() called')
    
    template = """*Alert from Recorded Futures App for Phantom - threat hunting playbook*

>When processing the potentially malicious destination IP *{0}* with a Risk Score of *{1}*, the playbook have found one or more of its related entities present in Splunk. 
>
>The following number of entities with at least 10 references in Recorded Future recent events were found:
>IP Addresses:    *{2}* 
>Domains:    *{3}* 
>Files:    *{4}*
>Vulnerabilities:    *{5}*
>
>More details are available in Phantom: https://phantom-qa-45-03{6}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation_1:action_result.data.*.name",
        "ip_reputation_1:action_result.data.*.riskscore",
        "splunksearch_for_ip:action_result.summary.total_events",
        "spunksearch_for_domains:action_result.summary.total_events",
        "splunksearch_for_files:action_result.summary.total_events",
        "spunksearch_for_vulns:action_result.summary.total_events",
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="slack_notification")

    send_message_2(container=container)

    return

def send_message_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_message_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_message_2' call
    formatted_data_1 = phantom.get_format_data(name='slack_notification')

    parameters = []
    
    # build parameters list for 'send_message_2' call
    parameters.append({
        'message': formatted_data_1,
        'destination': "# phantom-demo",
    })

    phantom.act("send message", parameters=parameters, assets=['slack'], name="send_message_2")

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