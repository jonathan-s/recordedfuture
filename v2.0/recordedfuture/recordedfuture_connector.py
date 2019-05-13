#
# File: recordedfuture_connector.py
#
# Copyright (c) Recorded Future, Inc., 2019
#
# This unpublished material is proprietary to Recorded Future.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Recorded Future.
#
# ---------------------------------------------
# Phantom Recorded Future Connector python file
# ---------------------------------------------

# Global imports
import os

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from recordedfuture_consts import *
import requests
import urllib
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RecordedfutureConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(RecordedfutureConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    @staticmethod
    def _process_empty_response(response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(
            phantom.APP_ERROR,
            "Empty response and no information in the header"),
            None)

    @staticmethod
    def _process_html_response(response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception as err:
            error_text = "Cannot parse error details: %s" % err

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code,
            error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    @staticmethod
    def _process_json_response(resp, action_result):

        # Try a json parse
        try:
            resp_json = resp.json()
        except Exception as err:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Unable to parse JSON response. Error: {0}".format(str(err))),
                None)

        # Please specify the status codes here
        if 200 <= resp.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        if resp.status_code == 404:
            return RetVal(phantom.APP_SUCCESS, {})

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} " \
                  "Data from server: {1}".format(resp.status_code,
                                                 resp.text.replace(
                                                     u'{',
                                                     '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _process_response(self, resp, action_result):
        # store the r_text in debug data, it will get dumped in the logs if
        # the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': resp.status_code})
            action_result.add_debug_data({'r_text': resp.text})
            action_result.add_debug_data({'r_headers': resp.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in resp.headers.get('Content-Type', ''):
            return self._process_json_response(resp, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in resp.headers.get('Content-Type', ''):
            return self._process_html_response(resp, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not resp.text:
            return self._process_empty_response(resp, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} " \
                  "Data from server: {1}".format(resp.status_code,
                                                 resp.text.replace(
                                                     '{',
                                                     '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request
        # accepts
        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   "Invalid method: {0}".format(
                                                       method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        # Create a HTTP_USER_AGENT header
        platform = 'Phantom_%s' % self.get_product_version()
        user_agent = '{app_name} ({platform}) {pkg_name}/{pkg_version}'.format(
            app_name=os.path.basename(__file__),
            pkg_name='phantom',
            pkg_version=version,
            platform=platform)

        # headers
        my_headers = {
            'X-RFToken': config.get('recordedfuture_api_token'),
            'User-Agent': user_agent
        }

        try:
            resp = request_func(
                url,
                headers=my_headers,
                verify=config.get('verify_server_cert', False),
                **kwargs)
        except Exception as err:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Error Connecting to server. Details: {0}".format(str(err))),
                resp_json)

        return self._process_response(resp, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        # make rest call
        my_ret_val, response = self._make_rest_call('/domain/google.com',
                                                    action_result)

        if phantom.is_fail(my_ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_reputation(self, param, path_info, fields):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the
        # platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # Params for the API call
        params = {
            'fields': ','.join(fields)
        }

        # make rest call
        my_ret_val, response = self._make_rest_call(path_info,
                                                    action_result,
                                                    params=params)

        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        if response == {}:
            return action_result.set_status(phantom.APP_SUCCESS)

        # Now post process the data,  uncomment code as you deem fit
        res = response['data']
        # if 'relatedEntities' in res:
        #     relatedEntities = res['relatedEntities']
        #     res['relatedEntities'] = {}
        #     for i in relatedEntities:
        #         res['relatedEntities'][i['type']] = []
        #         for entity in i['entities']:
        #             res['relatedEntities'][i['type']].append(
        #                 {'name': entity['entity']['name'],
        #                  'refCount': entity['count']})
        action_result.add_data(res)
        self.save_progress('Added data with keys {}', res.keys())
        summary = action_result.get_summary()
        if 'risk' in res:
            if 'criticalityLabel' in res['risk']:
                summary['criticalityLabel'] = res['risk']['criticalityLabel']
            if 'riskSummary' in res['risk']:
                summary['riskSummary'] = res['risk']['riskSummary']
        if 'timestamps' in res:
            if 'lastSeen' in res['timestamps']:
                summary['lastSeen'] = res['timestamps']['lastSeen']
        action_result.set_summary(summary)

        # Add the response into the data section
        # action_result.add_data(res)

        # Add a dictionary that is made up of the most important values from
        # data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary
        # dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set
        # the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR,
        #                                 "Action not yet implemented")

    def _parse_rule_data(self, res):
        from collections import defaultdict
        entities = defaultdict(list)
        for ent in res.get('entities', []):
            if ent['entity'] is not None:
                entities[ent['entity']['type']].append(ent['entity']['name'])
            for doc in ent.get('documents'):
                for ref in doc.get('references'):
                    for entity in ref.get('entities'):
                        entities[entity['type']].append(entity['name'])
        return entities

    def _handle_alert_data_lookup(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the
        # platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        rule_id = param['rule_id']
        timeframe = param['timeframe']
        assert rule_id is not None
        assert timeframe is not None

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')
        params = {
            'rule_id': param['rule_id'],
            'triggered': param['timeframe']
        }

        # make rest call
        my_ret_val, response = self._make_rest_call('/alert/search',
                                                    action_result,
                                                    params=params)

        if phantom.is_fail(my_ret_val):
            # the call to the 3rd party device or service failed, action
            # result should contain all the error details
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        for alert in response['data']['results']:
            url2 = '/alert/%s' % alert['id']
            ret_val2, response2 = self._make_rest_call(url2, action_result)
            entities = self._parse_rule_data(response2['data'])

            # Add the response into the data section
            current_alert = {
                'alertTitle': response2['data']['title'],
                'triggered': response2['data']['triggered'],
                'alertUrl': response2['data']['url'],
                'entities': entities
            }
            action_result.add_data({'alert': current_alert})
            self.save_progress('Alert: "%s" triggered "%s"'
                               % (response2['data']['title'],
                                  response2['data']['triggered']))

        # Add a dictionary that is made up of the most important values from
        # data into the summary
        summary = action_result.get_summary()
        summary['total_number_of_alerts'] = response['counts']['total']
        summary['returned_number_of_alerts'] = response['counts']['returned']
        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary
        # dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_rule_id_lookup(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the
        # platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        params = {
            'freetext': param['rule_name'],
            'limit': 100
        }

        # make rest call
        my_ret_val, response = self._make_rest_call('/alert/rule',
                                                    action_result,
                                                    params=params)

        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        for result in response['data'].values():
            for rule in result:
                action_result.add_data({'rule': rule})

        # Add a dictionary that is made up of the most important values from
        # data into the summary
        summary = action_result.get_summary()
        summary['total_number_of_rules'] = response['counts']['total']
        summary['returned_number_of_rules'] = response['counts']['returned']

        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the
        # summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        my_ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            my_ret_val = self._handle_test_connectivity(param)

        elif action_id == 'domain_reputation':
            fields = ["timestamps", "risk", "threatLists",
                      "intelCard", "metrics", "relatedEntities"]
            path_info = '/domain/idn:%s' % param['domain']
            my_ret_val = self._handle_reputation(param, path_info, fields)

        elif action_id == 'url_reputation':
            fields = ["timestamps", "risk", "metrics", "relatedEntities"]
            path_info = '/url/%s' % urllib.quote_plus(param["url"])
            my_ret_val = self._handle_reputation(param, path_info, fields)

        elif action_id == 'ip_reputation':
            fields = ["timestamps", "risk", "threatLists", "intelCard",
                      "metrics", "location", "relatedEntities"]
            path_info = '/ip/%s' % param['ip']
            my_ret_val = self._handle_reputation(param, path_info, fields)

        elif action_id == 'file_reputation':
            fields = ["timestamps", "risk", "threatLists", "intelCard",
                      "metrics", "hashAlgorithm", "relatedEntities"]
            path_info = '/hash/%s' % param['hash']
            my_ret_val = self._handle_reputation(param, path_info, fields)

        elif action_id == 'lookup_vulnerability':
            fields = ["timestamps", "risk", "threatLists", "intelCard",
                      "metrics", "cvss", "nvdDescription", "relatedEntities"]
            path_info = '/vulnerability/%s' % urllib.quote(
                param['vulnerability'], safe='')
            my_ret_val = self._handle_reputation(param, path_info, fields)

        elif action_id == 'rule_id_lookup':
            my_ret_val = self._handle_rule_id_lookup(param)

        elif action_id == 'alert_data_lookup':
            my_ret_val = self._handle_alert_data_lookup(param)

        return my_ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('recordedfuture_api_basename')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(
                e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RecordedfutureConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
