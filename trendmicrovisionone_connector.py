# File: trendmicrovisionone_connector.py

# Copyright (c) Trend Micro, 2022

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import base64
import datetime
import json
import re
import sys
import time
import uuid

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom import vault
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from trendmicrovisionone_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TrendMicroVisionOneConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(TrendMicroVisionOneConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
        )

    def header(self):
        return {
            "Authorization": "Bearer {token}".format(token=self.api_key),
            "Content-Type": "application/json;charset=utf-8",
            "User-Agent": "TMV1SplunkSOARApp/1.0",
        }

    def _process_html_response(self, response, action_result):
        # A html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_file_response(self, r, action_result):
        # Just send back the file stream data
        if r.status_code == 200:
            data = r.content
            return RetVal(phantom.APP_SUCCESS, data)

        else:
            message = "Error from server. Status Code: {0}".format(r.status_code)
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # Try manual octet stream return
        if r.headers.get("Content-Type", "") == "binary/octet-stream":
            return self._process_file_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # return 200 response that did not fit any above handle
        if r.status_code == 200:
            return self._process_file_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)
                ),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get("verify_server_cert", False),
                **kwargs,
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e)),
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            ADD_OBJECT_TO_EXCEPTION_LIST,
            action_result,
            params=None,
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_computer_id(self, field, value):
        # get the computer id from Trend Micro Vision One

        body = {"criteria": {"field": field, "value": value}}
        response = requests.post(
            f"{self._base_url}{GET_COMPUTER_ID_ENDPOINT}",
            headers=self.header(),
            data=json.dumps(body),
            timeout=30,
        ).json()

        if response["status"] == "FAIL":
            return "lookup failed"
        computer_id = response.get("result").get("computerId")

        return computer_id

    def delistify(self, listed):
        # Unpack and get the first element in a list of any depth
        if isinstance(listed, list) or "[" in listed:
            if isinstance(listed, list):
                return self.delistify(listed[0])
            elif "'" in listed:
                liste = listed.split("'")
                return self.delistify(liste[1])
            elif '"' in listed:
                liste = listed.split('"')
                return self.delistify(liste[1])
        else:
            return listed

    def _handle_get_computer_id(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        ip_hostname_mac = param["ip_hostname_mac"]
        lookup_type = self.lookup_type(ip_hostname_mac)
        body = {"criteria": {"field": lookup_type, "value": ip_hostname_mac}}

        # make rest call
        ret_val, response = self._make_rest_call(
            GET_COMPUTER_ID_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Computer ID lookup failed.")
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def lookup_type(self, param):

        # Regex expression for validating IPv4
        regex = (
            "(([0-9]|[1-9][0-9]|1[0-9][0-9]|"
            "2[0-4][0-9]|25[0-5])\\.){3}"
            "([0-9]|[1-9][0-9]|1[0-9][0-9]|"
            "2[0-4][0-9]|25[0-5])"
        )

        # Regex expression for validating IPv6
        regex1 = "((([0-9a-fA-F]){1,4})\\:){7}" "([0-9a-fA-F]){1,4}"

        # Regex expression for validating MAC
        regex2 = "([0-9A-Fa-f]{2}[:-]){5}" "([0-9A-Fa-f]{2})"

        p = re.compile(regex)
        p1 = re.compile(regex1)
        p2 = re.compile(regex2)

        # Checking if it is a valid IPv4 address
        if re.search(p, param):
            return "ip"

        # Checking if it is a valid IPv6 address
        elif re.search(p1, param):
            return "ipv6"

        # Checking if it is a valid MAC address
        elif re.search(p2, param):
            return "macaddr"

        # Otherwise use hostname type
        return "hostname"

    def _handle_get_endpoint_info(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        value = param["ip_hostname_mac"]
        if "-" in value:
            parts = value.split("-")
            value = ":".join(parts)

        # Unpack first item from a list of any depth
        value = self.delistify(value)
        field = self.lookup_type(value)
        computer_id = self.get_computer_id(field, value)
        body = {"computerId": computer_id}

        # make rest call
        ret_val, response = self._make_rest_call(
            GET_ENDPOINT_INFO_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            params=None,
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Endpoint info lookup failed.")
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_device(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        value = param["ip_hostname_mac"]
        value = self.delistify(value)
        field = self.lookup_type(value)
        computerid = self.get_computer_id(field, value)
        productid = param["productid"]
        description = param.get("description", "")
        body = {
            "computerId": computerid,
            "productId": productid,
            "description": description,
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            ISOLATE_CONNECTION_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            params=None,
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Quarantine endpoint failed.")
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        # print(action_result._ActionResult__data)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def process_artifacts(
        self, indicators, imp_scope, severity, start_time, types, container
    ):
        # check if artifact exists, create anew if it doesn't
        artifact_id = indicators.get("id", None)
        artifact_type = indicators.get("objectType", "")
        artifact_value = indicators.get("objectValue", "")
        related_entities = indicators.get("relatedEntities", [])
        # filter_id = indicators.get('filterId', []) #not going to pass filter_id

        # extract related entity data
        try:
            local_scope = {}
            if artifact_id:
                for scope in imp_scope:
                    # make listy dict in case there will be a plethora of related entities
                    local_scope["entityValue"] = []
                    local_scope["entityId"] = []
                    local_scope["relatedEntities"] = []
                    local_scope["relatedIndicators"] = []
                    local_scope["entityType"] = []
                    # extract data
                    entity_v = scope.get("entityValue", "")
                    entity_i = scope.get("entityId", "")
                    related_e = scope.get("relatedEntities", "")  # list
                    related_i = scope.get("relatedIndicators", "")  # list
                    entity_t = scope.get("entityType", "")
                    # append data to listy dict in case artefact is indeed related
                    if artifact_id in related_i:
                        local_scope["entityValue"].append(entity_v)
                        local_scope["entityId"].append(entity_i)
                        local_scope["relatedEntities"].append(related_e)
                        local_scope["relatedIndicators"].append(related_i)
                        local_scope["entityType"].append(entity_t)
        except Exception as e:
            self.debug_print(
                f"The following error happened while localizing artefact impact scope: {e}"
            )

        # if artifacts dont already exist, make new artifact bundles
        new_artifacts = []
        try:
            if not self.artifact_exists(f"TM-{container}-{artifact_id}", container):
                new_artifacts.append(
                    self.create_artifact(
                        artifact_id,
                        artifact_type,
                        artifact_value,
                        related_entities,
                        local_scope,
                        severity,
                        start_time,
                        types,
                        container,
                    )
                )
        except Exception as e:
            self.debug_print(
                f"The following error happened while creating new artifact bundle: {e}"
            )
            pass

        # save artifacts to splunk
        if new_artifacts:
            ret_val, msg, response = self.save_artifacts(new_artifacts)
            if phantom.is_fail(ret_val):
                self.save_progress(f"Error saving artifacts: {msg}")
                self.debug_print(f"Error saving artifacts: {new_artifacts}")

    def create_artifact(
        self,
        artifact_id,
        artifact_type,
        artifact_value,
        related_entities,
        local_scope,
        severity,
        start_time,
        types,
        container,
    ):
        # create new artifact
        artifact = {}
        artifact["name"] = artifact_id
        artifact["label"] = artifact_type
        artifact["container_id"] = container
        artifact["source_data_identifier"] = f"TM-{container}-{artifact_id}"
        artifact["type"] = local_scope.get("entityType", "network")
        artifact["severity"] = severity
        artifact["start_time"] = start_time

        art_cef = {}
        # Map attributes returned from TM Vision One into Common Event Format (cef)
        art_cef["cs1"] = artifact_value
        art_cef["cs1Label"] = "Artifact Value"
        art_cef["cs2"] = related_entities
        art_cef["cs2Label"] = "Related Entities"
        art_cef["cs3"] = types
        art_cef["cs3Label"] = "Product ID"
        hosts_names = []
        assoc_ips = []
        if isinstance(local_scope["entityValue"], list):
            for i in local_scope["entityValue"]:
                hosts_names.append(i.get("name", ""))
                assoc_ips.append(i.get("ips", ""))
        art_cef["sourceHostName"] = hosts_names
        art_cef["sourceAddress"] = assoc_ips

        artifact["cef"] = art_cef

        return artifact

    def update_container(self, i, old_container):
        # update old container
        update = {}
        update["data"] = i
        sdi = i.get("workbenchId", "")
        types = i["detail"].get("alertProvider", "")
        update["description"] = f"{sdi}: {types}"
        imp_scope = i["detail"]["impactScope"]
        severity = i.get("severity", "")
        start_time = i.get("createdTime", "")

        url = f"{self.get_phantom_base_url()}rest/container/{old_container}"
        try:
            # nosemgrep
            requests.post(url, data=json.dumps(update), verify=False, timeout=30)
            # the above requests to create artefacts only work with verify=False
        except Exception:
            return phantom.APP_ERROR

        # add new artifacts
        for x in i["detail"]["indicators"]:
            self.process_artifacts(
                x, imp_scope, severity, start_time, types, container=old_container
            )

    def artifact_exists(self, sdi, container):
        # check if a given artifact exists for in a container
        url = f'{self.get_phantom_base_url()}rest/artifact?_filter_source_data_identifier="{sdi}"&_filter_container_id={container}'
        # make rest call
        try:
            self.debug_print(f"Making request on url: {url}")
            response = requests.get(url, verify=False, timeout=30)  # nosemgrep
        except Exception:
            return None
        # return id or None
        if response.json().get("data", None):
            return response.json().get("data", None)[0].get("id", None)
        else:
            return None

    def container_exists(self, sdi):
        # check if TM workbenchID already exists in Splunk
        url = f'{self.get_phantom_base_url()}rest/container?_filter_source_data_identifier="{sdi}"&_filter_asset={self.get_asset_id()}'
        # make rest call
        try:
            response = requests.get(url, verify=False, timeout=30)  # nosemgrep
        except Exception:
            return None
        # return id or None
        if response.json().get("data", None):
            return response.json().get("data", None)[0].get("id", None)
        else:
            return None

    def create_container(self, i, sdi):
        # create a new container for a Trend Micro WorkBench incident
        container = {}
        container["name"] = i["workbenchName"]
        container["source_data_identifier"] = sdi
        container["label"] = self.get_config().get("ingest", {}).get("container_label")
        container["description"] = i["detail"].get("description", "")
        container["data"] = i
        container["type"] = i["detail"].get("alertProvider", "")
        container["severity"] = i.get("severity", "")
        container["start_time"] = i.get("createdTime", "")

        return container

    def _handle_on_poll(self, param):
        # Log current action
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # standard time frame for poll interval
        nowstamp = int(datetime.datetime.utcnow().timestamp())
        end = (
            datetime.datetime.fromtimestamp(nowstamp).isoformat() + ".000Z"
        )  # default end is now
        monthago = nowstamp - 2500000  # 2,5 million unix epoch time ~ 1 month
        start = (
            datetime.datetime.fromtimestamp(monthago).isoformat() + ".000Z"
        )  # default start is approx. 1 month ago

        # frame time from last run, or do a first run with default timeframe
        try:
            starttime = self._state["last_ingestion_time"]
        except Exception:
            starttime = param.get("starttime", start)
        endtime = param.get("endtime", end)
        # DEBUG time frame
        # starttime = '2022-01-01T10:00:00.000Z'
        # endtime = '2022-04-12T12:00:00.000Z'
        # DEBUG time frame
        limit = param.get("limit", 100)

        query_params = {
            "endTime": endtime,
            "limit": limit,
            "offset": 0,
            "sortBy": "createdTime",
            "startTime": starttime,
        }

        ret_val, event_feed = self._make_rest_call(
            WORKBENCH_HISTORIES,
            action_result,
            method="get",
            headers=self.header(),
            params=query_params,
        )

        if event_feed is None:
            return action_result.get_status()

        # Get events from the TM Vision One and process them as Phantom containers
        try:
            events = event_feed
            for i in events["data"]["workbenchRecords"]:
                sdi = i.get("workbenchId", "")

                # check if container already exists
                old_container = self.container_exists(sdi)
                if old_container:
                    self.debug_print("Updating Containers")
                    self.update_container(i, old_container)
                else:
                    # make new container
                    container = self.create_container(i, sdi)
                    # save new container to Splunk
                    ret_val, msg, cid = self.save_container(container)
                    # get new containers id
                    old_container = self.container_exists(sdi)
                    # update new container with artifacts
                    self.update_container(i, old_container)
                    if phantom.is_fail(ret_val):
                        self.save_progress("Error saving container: {}".format(msg))
                        self.debug_print(
                            "Error saving container: {} -- CID: {}".format(msg, cid)
                        )

            # Log results
            action_result.add_data(events)
            summary = action_result.update_summary({})
            summary["Number of Events Found"] = len(events)
            self.save_progress("Phantom imported {0} events".format(len(events)))

            # remember current timestamp for next run
            self._state["last_ingestion_time"] = endtime

            return action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            self.save_progress("Exception = {0}".format(str(e)))
            return action_result.set_status(
                phantom.APP_ERROR, "Error getting events. Details: {0}".format(str(e))
            )

    def _handle_unquarantine_device(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        value = param["ip_hostname_mac"]
        value = self.delistify(value)
        field = self.lookup_type(value)
        computerid = self.get_computer_id(field, value)
        productid = param["productid"]
        description = param.get("description", "")
        body = {
            "computerId": computerid,
            "productId": productid,
            "description": description,
        }
        # make rest call
        ret_val, response = self._make_rest_call(
            RESTORE_CONNECTION_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            params=None,
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_status_check(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        action_id = param["action_id"]
        param = {"actionId": action_id}

        # make rest call
        ret_val, response = self._make_rest_call(
            TASK_DETAIL_ENDPOINT,
            action_result,
            method="get",
            params=param,
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Start looping for 20 minutes to wait for "ongoing" tasks to finish
        timer = 1200  # seconds
        elapsed = 0
        while timer > 0 and "success" not in response.get("data").get("taskStatus"):
            # make rest call
            ret_val, response = self._make_rest_call(
                TASK_DETAIL_ENDPOINT,
                action_result,
                method="get",
                params=param,
                headers=self.header(),
            )
            # sleep 5 secs
            time.sleep(5)
            timer -= 5
            elapsed += 5
            # abort if failed
            if phantom.is_fail(ret_val) or "failed" in response.get("data").get(
                "taskStatus"
            ):
                if "failed" in response.get("data").get("taskStatus"):
                    message = {"taskStatus": response.get("data").get("taskStatus")}
                    action_result.add_data(message)
                return action_result.get_status()

        # Add the message into the data section
        self.debug_print(
            "Approximate number of seconds waited for task to finish: %s" % elapsed
        )
        message = {"taskStatus": response.get("data").get("taskStatus")}
        action_result.add_data(message)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_to_blocklist(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        value_type = param["value_type"]
        target_value = param["target_value"]
        product_id = param.get("product_id", "sao")
        description = param.get("description", "Add item to blocklist.")
        body = {
            "valueType": value_type,
            "targetValue": target_value,
            "productId": product_id,
            "description": description,
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            ADD_BLOCKLIST_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_from_blocklist(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        value_type = param["value_type"]
        target_value = param["target_value"]
        product_id = param.get("product_id", "sao")
        description = param.get("description", "Remove item to blocklist.")
        body = {
            "valueType": value_type,
            "targetValue": target_value,
            "productId": product_id,
            "description": description,
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            REMOVE_BLOCKLIST_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_email_message(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        message_id = param["message_id"]
        mailbox = param["mailbox"]
        message_delivery_time = param.get("message_delivery_time", "")
        product_id = param.get("product_id", "sao")
        description = param.get("description", "Quarantine e-mail.")
        body = {
            "messageId": message_id,
            "mailBox": mailbox,
            "messageDeliveryTime": message_delivery_time,
            "productId": product_id,
            "description": description,
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            QUARANTINE_EMAIL_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_email_message(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        message_id = param["message_id"]
        mailbox = param["mailbox"]
        message_delivery_time = param.get("message_delivery_time", "")
        product_id = param.get("product_id", "sao")
        description = param.get("description", "Delete e-mail.")
        body = {
            "messageId": message_id,
            "mailBox": mailbox,
            "messageDeliveryTime": message_delivery_time,
            "productId": product_id,
            "description": description,
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            DELETE_EMAIL_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_terminate_process(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        value = param["ip_hostname_mac"]
        value = self.delistify(value)
        field = self.lookup_type(value)
        file_list = []
        product_id = param.get("product_id", "sao")
        description = param.get("description", "Terminate process.")
        file_sha1 = param["file_sha1"]
        filename = param.get("filename", "")
        computer_id = self.get_computer_id(field, value)
        if filename:
            file_list.append(filename)
        body = {
            "computerId": computer_id,
            "fileSha1": file_sha1,
            "productId": product_id,
            "description": description,
            "filename": file_list,
        }
        # make rest call
        ret_val, response = self._make_rest_call(
            TERMINATE_PROCESS_ENDPOINT,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def exception_list_count(self):
        # Gets the count of objects present in exception list
        ret_val, response = self._make_rest_call(
            ADD_OBJECT_TO_EXCEPTION_LIST,
            action_result="",
            method="get",
            params=None,
            headers=self.header(),
        )
        # response = json.loads(response.decode('utf-8')) #seems to not be needed anymore
        list_of_exception = response.get("data").get("exceptionList")
        exception_count = len(list_of_exception)
        return exception_count

    def _handle_add_to_exception(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        types = param["type"]
        types = self.delistify(types)
        value = param["value"]
        description = param.get("description", "")
        body = {"data": [{"type": types, "value": value}]}
        body["data"][0]["description"] = description

        # make rest call
        ret_val, response = self._make_rest_call(
            ADD_OBJECT_TO_EXCEPTION_LIST,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header()
            # params=None,
        )

        exception_list = self.exception_list_count()

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        data = {
            "message": "success",
            "status_code": action_result._ActionResult__debug_data[0]
            .split(":")[1]
            .split("}")[0],
            # there could be a better way to get the status code
            "total_items": exception_list,
        }
        action_result.add_data(data)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_from_exception(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        types = param["type"]
        types = self.delistify(types)
        value = param["value"]
        description = param.get("description", "")
        body = {"data": [{"type": types, "value": value}]}
        body["data"][0]["description"] = description

        # make rest call
        ret_val, response = self._make_rest_call(
            DELETE_OBJECT_FROM_EXCEPTION_LIST,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header()
            # params=None,
        )

        exception_list = self.exception_list_count()

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        data = {
            "message": "success",
            "status_code": action_result._ActionResult__debug_data[0]
            .split(":")[1]
            .split("}")[0],
            # there could be a better way to get the status code
            "total_items": exception_list,
        }
        action_result.add_data(data)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def suspicious_list_count(self):
        # Get the count of objects present n suspicious list
        ret_val, response = self._make_rest_call(
            ADD_OBJECT_TO_SUSPICIOUS_LIST,
            action_result="",
            method="get",
            params=None,
            headers=self.header(),
        )
        # response = json.loads(response.decode('utf-8'))
        list_of_exception = response.get("data").get("suspiciousObjectList")
        exception_count = len(list_of_exception)
        return exception_count

    def _handle_add_to_suspicious(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        types = param["type"]
        types = self.delistify(types)
        value = param["value"]
        description = param.get("description", "")
        scan_action = param.get("scan_action", "")
        if scan_action and scan_action not in ("log", "block"):
            raise "{0} is not a valid parameter. Kindly provide valid parameter".format(
                scan_action
            )
        risk_level = param.get("risk_level", "")
        if risk_level and risk_level not in ("high", "medium", "low"):
            raise "{0} is not a valid parameter. Kindly provide valid parameter".format(
                risk_level
            )
        expiry = param.get("expiry", 0)
        body = {
            "data": [
                {
                    "type": types,
                    "value": value,
                    "description": description,
                    "scanAction": scan_action,
                    "riskLevel": risk_level,
                    "expiredDay": expiry,
                }
            ]
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            ADD_OBJECT_TO_SUSPICIOUS_LIST,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        suspicious_list = self.suspicious_list_count()

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        data = {
            "message": "success",
            "status_code": action_result._ActionResult__debug_data[0]
            .split(":")[1]
            .split("}")[0],
            # there could be a better way to get the status code
            "total_items": suspicious_list,
        }
        action_result.add_data(data)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_from_suspicious(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        types = param["type"]
        types = self.delistify(types)
        value = param["value"]
        body = {"data": [{"type": types, "value": value}]}

        # make rest call
        ret_val, response = self._make_rest_call(
            DELETE_OBJECT_FROM_SUSPICIOUS_LIST,
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        suspicious_list = self.suspicious_list_count()

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        data = {
            "message": "success",
            "status_code": action_result._ActionResult__debug_data[0]
            .split(":")[1]
            .split("}")[0],
            # there could be a better way to get the status code
            "total_items": suspicious_list,
        }
        action_result.add_data(data)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_check_analysis_status(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        task_id = param["task_id"]

        # make rest call
        ret_val, response = self._make_rest_call(
            GET_FILE_STATUS.format(taskId=task_id),
            action_result,
            method="get",
            params=None,
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def file_to_vault(self, data, filename, container_id, action_result):
        filename += "@" + str(uuid.uuid4())
        try:
            #  Upload file to vault
            ret_val, response, vault_id = vault.Vault.create_attachment(
                data, container_id, filename
            )
            if ret_val:
                self.debug_print(
                    f"Successfully created vault file: {filename} in vault: {vault_id}"
                )
                success_info = {
                    phantom.APP_JSON_VAULT_ID: vault_id,
                    "file_name": filename,
                }
                return phantom.APP_SUCCESS, success_info
            raise Exception(f"Error during create attachment: {response}")
        except Exception as err:
            self.debug_print(err)
        return action_result.set_status(
            phantom.APP_ERROR, "Failed to create vault file"
        )

    def _handle_download_analysis_report(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        report_id = param["report_id"]
        types = param["type"]
        if types not in ("vaReport", "investigationPackage", "suspiciousObject"):
            raise TypeError("Kindly provide valid file 'type'")
        params = {"type": types}

        # make rest call
        ret_val, response = self._make_rest_call(
            GET_FILE_REPORT.format(reportId=report_id),
            action_result,
            method="get",
            params=params,
            headers=self.header(),
            stream=True,
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if isinstance(response, dict):
            # add response to results here
            message = {
                "message": response.get("message", ""),
                "code": response.get("code", ""),
                "data": [],
            }
            if len(response.get("data", [])) > 0:
                for data in response.get("data", {}):
                    data_value = {
                        "type": data.get("type", ""),
                        "value": data.get("value", ""),
                        "risk_level": data.get("riskLevel", ""),
                        "analysis_completion_time": data.get(
                            "analysisCompletionTime", ""
                        ),
                        "expired_time": data.get("expiredTime", ""),
                        "root_file_sha1": data.get("rootFileSha1", ""),
                    }
                    message.get("data", {}).append(data_value)

            container = {}
            container["name"] = report_id
            container[
                "source_data_identifier"
            ] = "File Analysis Report - Suspicious Object"
            container["label"] = "trendmicro"
            try:
                container["severity"] = message["data"][0]["risk_level"].capitalize()
            except Exception:
                container["severity"] = "Medium"
            container["tags"] = "suspiciousObject"
            ret_val, msg, cid = self.save_container(container)

            artifacts = []
            for i in message["data"]:
                artifacts_d = {}
                artifacts_d["name"] = "Artifact of {}".format(report_id)
                artifacts_d[
                    "source_data_identifier"
                ] = "File Analysis Report - Suspicious Object"
                artifacts_d["label"] = "trendmicro"
                artifacts_d["container_id"] = cid
                artifacts_d["cef"] = i
                artifacts.append(artifacts_d)
            ret_val, msg, cid = self.save_artifacts(artifacts)

            self.save_progress("Suspicious Object added to Container")

        else:
            data = response
            if types == "vaReport":
                results = self.file_to_vault(
                    data,
                    "Sandbox_Analysis_Report.pdf",
                    self.get_container_id(),
                    action_result,
                )
            else:
                results = self.file_to_vault(
                    data,
                    "Sandbox_Investigation_Package.zip",
                    self.get_container_id(),
                    action_result,
                )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        try:
            action_result.add_data(results)
        except Exception as e:
            self.debug_print(e)
            action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_collect_forensic_file(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        value = param["ip_hostname_mac"]
        value = self.delistify(value)
        field = self.lookup_type(value)
        computer_id = self.get_computer_id(field, value)
        product_id = param["product_id"].lower()
        file_path = param["file_path"]  # WARNING! filepath needs to be tuple!!!
        os = param.get("os")
        description = param.get("description", "")

        body = {
            "description": description,
            "productId": product_id,
            "computerId": computer_id,
            "filePath": file_path,
            "os": os,
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            COLLECT_FORENSIC_FILE,
            action_result,
            method="post",
            params=None,
            headers=self.header(),
            data=json.dumps(body),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_forensic_file_info(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        action_id = param["action_id"]
        param = {"actionId": action_id}

        # make rest call
        ret_val, response = self._make_rest_call(
            DOWNLOAD_INFORMATION_COLLECTED_FILE,
            action_result,
            method="get",
            params=param,
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_analysis(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        file_url = param["file_url"]
        file_name = param["file_name"]
        data = {}
        params = {}
        document_pass = param.get("document_pass", "")
        if document_pass:
            data["documentPassword"] = base64.b64encode(
                document_pass.encode("ascii")
            ).decode("ascii")
        else:
            data["documentPassword"] = ""
        archive_pass = param.get("archive_pass", "")
        if archive_pass:
            data["archivePassword"] = base64.b64encode(
                archive_pass.encode("ascii")
            ).decode("ascii")
        else:
            data["archivePassword"] = ""

        header = {"Authorization": "Bearer " + self.api_key}

        # make rest call
        try:
            file_content = requests.get(file_url, allow_redirects=True, timeout=30)
            files = {
                "file": (
                    file_name,
                    file_content.content,
                    "application/x-zip-compressed",
                )
            }
            ret_val, response = self._make_rest_call(
                SUBMIT_FILE_TO_SANDBOX,
                action_result,
                method="post",
                params=params,
                headers=header,
                data=data,
                files=files,
            )
        # except HTTPError as http_err:
        #    raise http_err
        except Exception as e:
            raise e

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_note(self, param):
        # Send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        workbench_id = param["workbench_id"]
        content = param["content"]

        body = {"content": content}

        # make rest call
        ret_val, response = self._make_rest_call(
            ADD_NOTE_ENDPOINT.format(workbenchId=workbench_id),
            action_result,
            method="post",
            data=json.dumps(body),
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_status(self, param):
        # Send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        workbench_id = param["workbench_id"]
        status = param["status"]

        if status == "new":
            update_status = 0  # NEW
        elif status == "in_progress":
            update_status = 1  # IN_PROGRESS
        elif status == "resolved_true_positive":
            update_status = 2  # RESOLVED_TRUE_POSITIVE
        elif status == "resolved_false_positive":
            update_status = 3  # RESOLVED_FALSE_POSITIVE

        body = {"investigationStatus": update_status}

        # make rest call
        ret_val, response = self._make_rest_call(
            UPDATE_STATUS_ENDPOINT.format(workbenchId=workbench_id),
            action_result,
            method="put",
            data=json.dumps(body),
            headers=self.header(),
        )

        if phantom.is_fail(ret_val):
            self.debug_print(
                "REST call failed, please check your endpoints and/or params"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        action_dict = {
            "get_computer_id": self._handle_get_computer_id,
            "get_endpoint_info": self._handle_get_endpoint_info,
            "quarantine_device": self._handle_quarantine_device,
            "unquarantine_device": self._handle_unquarantine_device,
            "status_check": self._handle_status_check,
            "add_to_blocklist": self._handle_add_to_blocklist,
            "quarantine_email_message": self._handle_quarantine_email_message,
            "terminate_process": self._handle_terminate_process,
            "add_to_exception": self._handle_add_to_exception,
            "add_to_suspicious": self._handle_add_to_suspicious,
            "delete_from_suspicious": self._handle_delete_from_suspicious,
            "check_analysis_status": self._handle_check_analysis_status,
            "download_analysis_report": self._handle_download_analysis_report,
            "collect_forensic_file": self._handle_collect_forensic_file,
            "forensic_file_info": self._handle_forensic_file_info,
            "start_analysis": self._handle_start_analysis,
            "remove_from_blocklist": self._handle_remove_from_blocklist,
            "delete_email_message": self._handle_delete_email_message,
            "delete_from_exception": self._handle_delete_from_exception,
            "test_connectivity": self._handle_test_connectivity,
            "on_poll": self._handle_on_poll,
            "add_note": self._handle_add_note,
            "update_status": self._handle_update_status,
        }

        if action_id in action_dict.keys():
            ret_val = action_dict[action_id](param)

        return ret_val

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
        self.api_key = config["api_key"]
        self._base_url = config.get("api_url")

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

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
            login_url = TrendMicroVisionOneConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False, timeout=30)  # nosemgrep
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            # nosemgrep
            r2 = requests.post(
                login_url, verify=False, data=data, headers=headers, timeout=30
            )
            # the above requests to create artefacts only work with verify=False
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TrendMicroVisionOneConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == "__main__":
    main()
