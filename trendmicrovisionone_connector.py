# File: trendmicrovisionone_connector.py

# Copyright (c) Trend Micro, 2022-2023

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

import re
import json
import os
import sys
import time
import uuid
import base64
import pytmv1
import requests
from datetime import datetime
from collections import defaultdict
from typing import Any, List, Dict, Optional, Union, Tuple
from pytmv1 import ImpactScope, HostInfo, SaeAlert, TiAlert, Indicator, Entity

# Phantom App imports
from phantom import vault
from bs4 import BeautifulSoup
import phantom.app as phantom
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
        self.app = "Trend Micro Vision One V3"
        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url: str = ""

    def _get_client(self) -> pytmv1.Client:  # type: ignore
        return pytmv1.client(self.app, self.api_key, self._base_url)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize pytmv1 client
        client = self._get_client()

        # Make API Call
        response = client.check_connectivity()

        if phantom.is_fail(response.result_code):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_endpoint_info(self, param):
        """
        Fetches information for an endpoint.
        Args:
            param: str: endpoint and query operator
        Returns:
            List[Any]: Returns a list of objects containing information about an endpoint
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        endpoint: str = param["ip_hostname_mac"]
        query_op: str = param["query_op"]
        # Choose QueryOp Enum based on user choice
        if "or" in query_op:
            query_op = pytmv1.QueryOp.OR
        elif "and" in query_op:
            query_op = pytmv1.QueryOp.AND

        # Initialize pytmv1 client
        client = self._get_client()

        new_endpoint_data = []
        # make rest call
        try:
            client.consume_endpoint_data(
                lambda endpoint_data: new_endpoint_data.append(endpoint_data.json()),
                pytmv1.QueryOp(query_op),
                endpoint,
            )
        except Exception as e:
            return e
        # Load json objects to list
        endpoint_data_resp = []
        for i in new_endpoint_data:
            endpoint_data_resp.append(json.loads(i))

        if len(endpoint_data_resp) == 0:
            self.save_progress(
                f"Endpoint lookup failed, please check endpoint name: {endpoint}"
            )
            return

        # Add the response into the data section
        action_result.add_data(endpoint_data_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_device(self, param):
        """_summary_

        Args:
            param (endpoint_identifiers): Object containing Endpoint name and (optional) description.

        Returns:
            List[Any]: Returns a list of objects containing task_id and HTTP status code
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize Pytmv1
        client = self._get_client()

        # Param setup
        endpoint_identifiers = json.loads(param.get("endpoint_identifiers"))
        multi_resp = {"multi_response": []}
        # make rest call
        for i in endpoint_identifiers:
            response = client.isolate_endpoint(
                pytmv1.EndpointTask(
                    endpointName=i["endpoint"], description=i.get("description", "")
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        if phantom.is_fail(response.result_code):
            self.save_progress("Quarantine endpoint failed.")
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_new_artifact_from_indicator(
        self, container_id: int, alert: Union[SaeAlert, TiAlert], indicator: Indicator
    ):
        """
        Create a new artifact from indicator.
        Args:
            container_id (int): ID that will be used to query for containers
            alert (Union[SaeAlert, TiAlert]): SAEAlert or TiAlert object
            indicator (Indicator): Indicator object

        Raises:
            RuntimeError: Raise error if artifact creation encounters a problem
        """
        # if artifacts dont already exist, make new artifact bundles
        if self.artifact_exists(container_id, alert.id, indicator.id):
            return

        artifact_related_entities: List[Entity] = []
        for entity in alert.impact_scope.entities:
            # append data to artifact related entities list in case artifact is indeed related
            if indicator.id in entity.related_indicator_ids:
                artifact_related_entities.append(entity)

        new_artifact = self._create_artifact_content(
            container_id,
            alert,
            indicator,
            artifact_related_entities,
        )

        ret_val, msg, response = self.save_artifacts([new_artifact])
        if phantom.is_fail(ret_val):
            self.save_progress(f"Error saving artifacts: {msg}")
            raise RuntimeError(f"Error saving artifacts: {[new_artifact]}")

    @staticmethod
    def create_artifact_identifier(alert_id: str, artifact_id: int) -> str:
        """
        Returns string artifact identifier.
        Args:
            alert_id (str): Alert ID.
            artifact_id (int): Artifact ID.

        Returns:
            str: Artifact identifier string.
        """
        return f"TM-{alert_id}-{str(artifact_id)}"

    def _create_artifact_content(
        self,
        container_id: int,
        alert: Union[SaeAlert, TiAlert],
        indicator: Indicator,
        local_scope: List[Entity],
    ):
        """
        Gathers information and adds to artifact.
        Args:
            container_id (int): Container ID.
            alert (Union[SaeAlert, TiAlert]): Type of alert (SaeAlert or TiAlert).
            indicator (Indicator): Indicators fetched from alert.
            local_scope (List[Entity]): Entities fetched from Impact Scope.

        Returns:
            dict[str, Any]: Artifact object.
        """
        art_cef = {
            "cs1": indicator.value.name
            if isinstance(indicator.value, HostInfo)
            else indicator.value,
            "cs1Label": "Artifact Value",
            "cs2": indicator.related_entities,
            "cs2Label": "Related Entities",
            "cs3": alert.alert_provider.value,
            "cs3Label": "Product ID",
        }
        hosts_names: List[str] = []
        assoc_ips: List[List[str]] = []

        # Note: Unsure, but may be a zipped mapping between host names and associated ips
        # Ex. Host names idx 0  may map to a list of ips in assoc_ips idx 0
        for entity in local_scope:
            value: Union[str, HostInfo] = entity.entity_value
            assert isinstance(value, HostInfo)

            hosts_names.append(value.name)
            assoc_ips.append(value.ips)

        art_cef["sourceHostName"] = hosts_names
        art_cef["sourceAddress"] = assoc_ips

        return {
            "name": indicator.id,
            "label": indicator.type,
            "container_id": container_id,
            "source_data_identifier": self.create_artifact_identifier(
                alert.id, indicator.id
            ),
            "type": [item.entity_type for item in local_scope],
            "severity": alert.severity.value,
            "start_time": alert.created_date_time,
            "cef": art_cef,
        }

    def _update_container_metadata(
        self, container_id: int, alert: Union[SaeAlert, TiAlert]
    ):
        """
        Updates an Alert container.
        Args:
            container_id (int): ID for the container.
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert

        Raises:
            RuntimeError: Raise a runtime error if container update fails.
        """
        # update old container
        container_alert_metadata: Dict[str, Any] = {
            "data": alert.dict(),
            "description": "{}: {}".format(container_id, alert.alert_provider.value),
        }
        try:
            requests.post(
                f"{self.get_phantom_base_url()}rest/container/{container_id}",
                data=json.dumps(container_alert_metadata),
                verify=False,
                timeout=30,
            )  # nosemgrep
        except Exception as e:
            raise RuntimeError(
                "Encountered an error updateding container alert."
            ) from e

    def artifact_exists(self, container_id: int, alert_id: str, indicator_id: int):
        """
        Makes a rest call to see if the artifact exists or not.
        Args:
            container_id (int): Container ID to filter.
            alert_id (str): Alert ID.
            indicator_id (int): Indicator ID.

        Returns:
            Boolean: True or False condition.
        """
        # Fetch the source data identifier
        sdi = self.create_artifact_identifier(alert_id, indicator_id)
        # check if a given artifact exists for in a container
        url = f'{self.get_phantom_base_url()}rest/artifact?_filter_source_data_identifier="{sdi}"&_filter_container_id={container_id}'
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

    def _get_existing_container_id(
        self, alert: Union[SaeAlert, TiAlert]
    ) -> Optional[int]:
        """
        Fetch container ID if it exists.
        Args:
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert.

        Raises:
            RuntimeError: Raise an error if container ID doesn't exist.

        Returns:
            Optional[int]: Return the container ID.
        """
        # check if TM workbenchID already exists in Splunk
        url = f'{self.get_phantom_base_url()}rest/container?_filter_source_data_identifier="{alert.id}"&_filter_asset={self.get_asset_id()}'
        # make rest call
        try:
            response = requests.get(url, verify=False, timeout=30)  # nosemgrep
        except Exception as e:
            raise RuntimeError(
                "Encountered an error getting the existing container ID from Phantom"
            ) from e

        # return id or None
        container_data: dict[str, Any] = response.json()
        if "data" not in container_data or len(container_data["data"]) == 0:
            return None
        # This direct access is okay because the values MUST exist otherwise the problem is out of scope.
        return container_data["data"][0]["id"]

    def _create_new_container_payload(
        self, alert: Union[SaeAlert, TiAlert]
    ) -> Dict[str, Any]:
        """
        Returns information for an Alert
        Args:
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert object.

        Returns:
            Dict[str, Any]: All pertinent data used to create container from Alert.
        """
        return {
            "name": alert.model,
            "source_data_identifier": alert.id,
            "label": self.get_config().get("ingest", {}).get("container_label"),
            "description": alert.description if isinstance(alert, SaeAlert) else "",
            "data": alert.dict(),
            "type": alert.alert_provider,
            "severity": alert.severity,
            "start_time": alert.created_date_time,
        }

    def _create_or_update_container(self, alert: Union[SaeAlert, TiAlert]) -> int:
        """
        Check if the container exists, if not then create a new container.
        Args:
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert object.

        Raises:
            RuntimeError: Raise a runtime error if container creation fails.

        Returns:
            int: The ID for the created container.
        """
        existing_container_id: Optional[int] = self._get_existing_container_id(alert)

        # If a container ID does not already exist, create a new one first, because the update operation
        # runs regardless of whether the container is new or existing.
        if existing_container_id is None:
            # save new container to Splunk using the alert
            ret_val, msg, cid = self.save_container(
                self._create_new_container_payload(alert)
            )

            if phantom.is_fail(ret_val):
                self.save_progress("Error saving container: {}".format(msg))
                raise RuntimeError(
                    "Error saving container: {} -- CID: {}".format(msg, cid)
                )

            existing_container_id = self._get_existing_container_id(alert)

            # Assertion made for type checking. At this point, the container ID will not be None if it was
            # successfully created.
            assert existing_container_id is not None
        return existing_container_id

    def _create_container_artifacts(
        self, container_id: int, alert: Union[SaeAlert, TiAlert]
    ):
        """
        Create an artifact for a container.
        Args:
            container_id (int): ID for the container.
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert object.
        """
        # add new artifacts
        for indicator in alert.indicators:
            self._create_new_artifact_from_indicator(container_id, alert, indicator)

    def _get_poll_interval(self, param) -> Tuple[datetime, datetime]:
        """
        Helper function for On Poll action to get poll interval.
        Args:
            param (str): starttime and endtime string in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC).

        Returns:
            Tuple[datetime, datetime]: start and end datetime.
        """
        # standard time frame for poll interval
        default_end_time = (
            datetime.fromtimestamp(int(datetime.utcnow().timestamp())).isoformat() + "Z"
        )
        start_time: str = param.get(
            "starttime", self._state.get("last_ingestion_time", "2020-06-15T10:00:00Z")
        )
        end_time: str = param.get("endtime", default_end_time)
        return start_time, end_time

    def _handle_on_poll(self, param):
        """
        Action to poll for Workbench Alerts.
        Args:
            param (_type_): starttime and endtime string in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC).

        Raises:
            RuntimeError: Raise an error if fetching Alerts fails.

        Returns:
            _type_: List containing Alert Objects.
        """
        # Log current action
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        start_time, end_time = self._get_poll_interval(param)

        # Initialize Pytmv1
        client = self._get_client()

        new_alerts: List[Union[SaeAlert, TiAlert]] = []
        # Make Rest call
        try:
            client.consume_alert_list(
                lambda alert: new_alerts.append(alert),
                start_time=start_time,
                end_time=end_time,
            )
        except Exception as e:
            raise RuntimeError("Consume Alert List failed.") from e

        # Get events from the TM Vision One and process them as Phantom containers
        try:
            for alert in new_alerts:
                # Use the container ID to create or update an Alert container
                container_id: int = self._create_or_update_container(alert)
                # Update container metadata
                self._update_container_metadata(container_id, alert)
                # Create artifacts for Alert containers
                self._create_container_artifacts(container_id, alert)

            # Log results
            serialized_alerts: List[Dict] = [item.dict() for item in new_alerts]
            action_result.add_data(serialized_alerts)
            summary = action_result.update_summary({})
            summary["Number of Events Found"] = len(serialized_alerts)
            self.save_progress(
                "Phantom imported {0} events".format(len(serialized_alerts))
            )

            # remember current timestamp for next run
            self._state["last_ingestion_time"] = end_time

            return action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            self.save_progress("Exception = {0}".format(str(e)))
            raise e

    def _handle_unquarantine_device(self, param):
        """
        Action to restore endpoint.
        Args:
            param (_type_): endpoint name and optional description.

        Returns:
            Dict[str,Any]: Object containing task_id and HTTP status code.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize Pytmv1
        client = self._get_client()

        # Param setup
        endpoint_identifiers = json.loads(param.get("endpoint_identifiers"))
        multi_resp = {"multi_response": []}
        # make rest call
        for i in endpoint_identifiers:
            response = client.restore_endpoint(
                pytmv1.EndpointTask(
                    endpointName=i["endpoint"], description=i.get("description", "")
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        if phantom.is_fail(response.result_code):
            self.save_progress("Quarantine endpoint failed.")
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_status_check(self, param):
        """
        Action to check the status of a task based on task_id.
        Args:
            param (str): Unique numeric string that identifies a response task.

        Returns:
            Dict[str, int]: object containing task_id and HTTP status code
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        task_id = param["task_id"]
        poll = param["poll"]

        # Optional Params
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.get_base_task_result(task_id, poll, poll_time_sec)

        if phantom.is_fail(response.result_code):
            return action_result.get_status()

        action_result.add_data(response.response.dict())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_to_blocklist(self, param):
        """
        Action to add item to block list.
        Args:
            param (Dict[str, str]): Object object made up of type, value and description.

        Returns:
            multi_resp: Object containing task_id and https status code.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        block_objects = json.loads(param["block_objects"])
        multi_resp = {"multi_response": []}
        # Choose enum
        for i in block_objects:
            if "domain" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.DOMAIN
            elif "ip" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.IP
            elif "filesha1" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA1
            elif "filesha256" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA256
            elif "sendermailaddress" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.SENDER_MAIL_ADDRESS
            elif "url" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.URL

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in block_objects:
            response = client.add_to_block_list(
                pytmv1.ObjectTask(
                    objectType=i["object_type"],
                    objectValue=i["object_value"],
                    description=i.get("description", ""),
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_from_blocklist(self, param):
        """
        Remove an item from block list.
        Args:
            param (block_objects): Object containing  type, value and (optional) description.

        Returns:
            multi_resp: Object containing task_id and https status code.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        block_objects = json.loads(param["block_objects"])
        multi_resp = {"multi_response": []}
        # Choose enum
        for i in block_objects:
            if "domain" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.DOMAIN
            elif "ip" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.IP
            elif "filesha1" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA1
            elif "filesha256" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA256
            elif "sendermailaddress" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.SENDER_MAIL_ADDRESS
            elif "url" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.URL

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in block_objects:
            response = client.remove_from_block_list(
                pytmv1.ObjectTask(
                    objectType=i["object_type"],
                    objectValue=i["object_value"],
                    description=i.get("description", ""),
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_email_message(self, param):
        """
        Action to quarantine an email using the mailBox and messageId or uniqueId
        Args:
            param (email_identifiers): Object containing mailBox/messageId and optional description or uniqueId and optional description.

        Returns:
            multi_resp: Object containing task_id and HTTP status code.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        email_identifiers = json.loads(param["email_identifiers"])
        multi_resp = {"multi_response": []}

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in email_identifiers:
            if i["message_id"].startswith("<") and i["message_id"].endswith(">"):
                response = client.quarantine_email_message(
                    pytmv1.EmailMessageIdTask(
                        messageId=i["message_id"],
                        description=i.get("description", ""),
                        mailbox=i.get("mailbox", ""),
                    )
                )
            else:
                response = client.quarantine_email_message(
                    pytmv1.EmailMessageUIdTask(
                        uniqueId=i["message_id"],
                        description=i.get("description", ""),
                    )
                )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

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
        email_identifiers = json.loads(param["email_identifiers"])
        multi_resp = {"multi_response": []}

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in email_identifiers:
            if i["message_id"].startswith("<") and i["message_id"].endswith(">"):
                response = client.delete_email_message(
                    pytmv1.EmailMessageIdTask(
                        messageId=i["message_id"],
                        description=i.get("description", ""),
                        mailbox=i.get("mailbox", ""),
                    )
                )
            else:
                response = client.delete_email_message(
                    pytmv1.EmailMessageUIdTask(
                        uniqueId=i["message_id"],
                        description=i.get("description", ""),
                    )
                )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

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
        process_identifiers = json.loads(param["process_identifiers"])
        multi_resp = {"multi_response": []}

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in process_identifiers:
            response = client.terminate_process(
                pytmv1.ProcessTask(
                    endpointName=i["endpoint"],
                    fileSha1=i["file_sha1"],
                    description=i.get("description", ""),
                    fileName=i.get("filename", ""),
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def exception_list_count(self) -> int:
        """Gets the count of objects present in exception list"""
        # Initialize Pytmv1
        client = self._get_client()
        new_exceptions = []
        try:
            client.consume_exception_list(
                lambda exception: new_exceptions.append(exception.dict())
            )
        except Exception as e:
            self.debug_print("Consume Exception List failed with following exception:")
            return e
        # Load json objects to list
        exception_objects = []
        for i in new_exceptions:
            i["description"] = "" if not i["description"] else i["description"]
            i = json.dumps(i)
            exception_objects.append(json.loads(i))
        exception_count = len(exception_objects)
        return exception_count

    def _handle_add_to_exception(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        block_objects = json.loads(param["block_objects"])
        multi_resp = {"multi_response": []}
        # Choose enum
        for i in block_objects:
            if "domain" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.DOMAIN
            elif "ip" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.IP
            elif "filesha1" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA1
            elif "filesha256" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA256
            elif "sendermailaddress" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.SENDER_MAIL_ADDRESS
            elif "url" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.URL

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in block_objects:
            response = client.add_to_exception_list(
                pytmv1.ObjectTask(
                    objectType=i["object_type"],
                    objectValue=i["object_value"],
                    description=i.get("description", ""),
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                items = response.response.dict().get("items")[0]
                items["task_id"] = (
                    "None" if items.get("task_id") is None else items["task_id"]
                )
                multi_resp["multi_response"].append(items)

        total_exception_count = self.exception_list_count()
        multi_resp["total_count"] = total_exception_count
        # Add the response into the data section
        action_result.add_data(multi_resp)

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
        block_objects = json.loads(param["block_objects"])
        multi_resp = {"multi_response": []}

        # Choose Enum
        for i in block_objects:
            if "domain" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.DOMAIN
            elif "ip" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.IP
            elif "filesha1" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA1
            elif "filesha256" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA256
            elif "sendermailaddress" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.SENDER_MAIL_ADDRESS
            elif "url" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.URL

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in block_objects:
            response = client.remove_from_exception_list(
                pytmv1.ObjectTask(
                    objectType=i["object_type"], objectValue=i["object_value"]
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                items = response.response.dict().get("items")[0]
                items["task_id"] = (
                    "None" if items.get("task_id") is None else items["task_id"]
                )
                multi_resp["multi_response"].append(items)

        total_exception_count = self.exception_list_count()
        multi_resp["total_count"] = total_exception_count
        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def suspicious_list_count(self) -> int:
        """Gets the count of objects present in suspicious list"""
        # Initialize Pytmv1
        client = self._get_client()
        new_suspicious = []
        try:
            client.consume_suspicious_list(
                lambda suspicious: new_suspicious.append(suspicious.dict())
            )
        except Exception as e:
            self.debug_print("Consume Suspicious List failed with following exception:")
            return e
        # Load json objects to list
        suspicious_objects = []
        for i in new_suspicious:
            i["description"] = "" if not i["description"] else i["description"]
            i = json.dumps(i)
            suspicious_objects.append(json.loads(i))
        suspicious_count = len(suspicious_objects)
        return suspicious_count

    def _handle_add_to_suspicious(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Parameter setup
        block_objects = json.loads(param.get("block_objects"))
        multi_resp = {"multi_response": []}

        # Choose enum
        for i in block_objects:
            if "domain" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.DOMAIN
            elif "ip" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.IP
            elif "filesha1" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA1
            elif "filesha256" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA256
            elif "sendermailaddress" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.SENDER_MAIL_ADDRESS
            elif "url" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.URL
            elif "block" in i["scan_action"].lower():
                i["scan_action"] = pytmv1.ScanAction.BLOCK
            elif "log" in i["scan_action"].lower():
                i["scan_action"] = pytmv1.ScanAction.LOG
            elif "high" in i["risk_level"].lower():
                i["risk_level"] = pytmv1.RiskLevel.HIGH
            elif "medium" in i["risk_level"].lower():
                i["risk_level"] = pytmv1.RiskLevel.MEDIUM
            elif "low" in i["risk_level"].lower():
                i["risk_level"] = pytmv1.RiskLevel.LOW

        # Initialize Pytmv1
        client = self._get_client()

        for i in block_objects:
            response = client.add_to_suspicious_list(
                pytmv1.SuspiciousObjectTask(
                    objectType=i["object_type"],
                    objectValue=i["object_value"],
                    scan_action=i.get("scan_action", "block"),
                    risk_level=i.get("risk_level", "medium"),
                    days_to_expiration=i.get("expiry_days", 30),
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                items = response.response.dict().get("items")[0]
                items["task_id"] = (
                    "None" if items.get("task_id") is None else items["task_id"]
                )
                multi_resp["multi_response"].append(items)

        total_suspicious_count = self.suspicious_list_count()
        multi_resp["total_count"] = total_suspicious_count
        action_result.add_data(multi_resp)

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
        block_objects = json.loads(param.get("block_objects"))
        multi_resp = {"multi_response": []}

        # Choose enum
        for i in block_objects:
            if "domain" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.DOMAIN
            elif "ip" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.IP
            elif "filesha1" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA1
            elif "filesha256" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.FILE_SHA256
            elif "sendermailaddress" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.SENDER_MAIL_ADDRESS
            elif "url" in i["object_type"].lower():
                i["object_type"] = pytmv1.ObjectType.URL

        # Initialize PYTMV1 Client
        app = "Trend Micro Vision One V3"
        token = self.api_key
        url = self._base_url
        client = pytmv1.client(app, token, url)

        # make rest call
        for i in block_objects:
            response = client.remove_from_suspicious_list(
                pytmv1.ObjectTask(
                    objectType=i["object_type"], objectValue=i["object_value"]
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                items = response.response.dict().get("items")[0]
                items["task_id"] = (
                    "None" if items.get("task_id") is None else items["task_id"]
                )
                multi_resp["multi_response"].append(items)

        total_suspicious_count = self.suspicious_list_count()
        multi_resp["total_count"] = total_suspicious_count
        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_sandbox_submission_status(self, param):
        """
        Checks the submission status for item(s) sent to sandbox for analysis.
        Args:
            submit_id: The Output ID  generated from Start-Analysis Command.

        Returns:
            Dict: Object containing response regarding submission status.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        submit_id = param["submit_id"]

        # Initialize Pytmv1
        client = self._get_client()

        # Make Action API Call
        response = client.get_sandbox_submission_status(submit_id=submit_id)
        if "error" in response.result_code.lower():
            return response
        else:
            # Add the response into the data section
            action_result.add_data(response.response.dict())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def file_to_vault(self, data, filename, container_id, action_result):
        # Create temp file for upload
        try:
            vault_dir = vault.get_vault_tmp_dir()
        except Exception as e:
            self.debug_print(e)
            vault_dir = "/opt/phantom/vault/tmp/"
        unique_id = str(uuid.uuid4())
        vault_dir += unique_id
        try:
            os.makedirs(vault_dir)
            fullpath = vault_dir + filename
            with open(fullpath, "wb") as f:
                f.write(data)
        except Exception as e:
            self.debug_print(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Failed to create vault file or directory"
            )

        # Upload file to vault
        ret_val, response, vault_id = vault.vault_add(container_id, fullpath, filename)

        # Erase temp data
        try:
            os.rmdir(vault_dir)
        except Exception as e:
            self.debug_print(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Failed erasing temporary vault related data"
            )

        # Return with vault creation details
        if ret_val:
            success_info = {phantom.APP_JSON_VAULT_ID: vault_id, "file_name": filename}
            return phantom.APP_SUCCESS, success_info

        # Failed to send file to vault
        self.debug_print(f"Failed to send file to vault: {response}")
        return action_result.set_status(
            phantom.APP_ERROR, "Failed to send file to vault"
        )

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

        # Required Params
        submit_id = param["submit_id"]
        poll = param["poll"]

        # Optional Params
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.download_sandbox_analysis_result(
            submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
        )

        if "error" in response.result_code.lower():
            return response
        else:
            # Make filename with timestamp
            name = "Trend_Micro_Sandbox_Analysis_Report "
            timestamp = time.time()
            date_time = datetime.fromtimestamp(timestamp)
            str_date_time = date_time.strftime("%d_%m_%Y_%H_%M_%S")
            file_name = str_date_time + name + ".pdf"

            results = self.file_to_vault(
                response.response.content,
                f"{file_name}",
                self.get_container_id(),
                action_result,
            )

        if phantom.is_fail(response.result_code):
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
        collect_files = json.loads(param.get("collect_files"))
        multi_resp = {"multi_response": []}

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in collect_files:
            response = client.collect_file(
                pytmv1.FileTask(
                    endpointName=i["endpoint"],
                    filePath=i["file_path"],
                    description=i.get("description", ""),
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_forensic_file_info(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        task_id = param["task_id"]
        poll = param["poll"]

        # Optional Params
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.get_base_task_result(
            task_id=task_id,
            poll=poll,
            poll_time_sec=poll_time_sec,
        )

        if phantom.is_fail(response.result_code):
            return action_result.get_status()

        file_info = response.response.dict()
        self.debug_print(f"FILE INFO: {file_info}")

        # Add the response into the data section
        action_result.add_data(file_info)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_analysis(self, param):
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize Pytmv1
        client = self._get_client()

        # Param setup
        file_url = param["file_url"]
        file_name = param.get("file_name", "Suspicious_File_Report.pdf")
        document_password = param.get("document_pass", "")
        archive_password = param.get("archive_pass", "")
        arguments = param.get("arguments", "None")

        response = client.submit_file_to_sandbox(
            file=file_url,
            file_name=file_name,
            document_password=document_password,
            archive_password=archive_password,
            arguments=arguments,
        )

        if phantom.is_fail(response.result_code):
            return action_result.get_status()

        else:
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

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        response = client.add_alert_note(alert_id=workbench_id, note=content)

        if phantom.is_fail(response.result_code):
            return action_result.get_status()

        location = response.response.location
        note_id = location.split("/")[-1]
        msg = "success"
        result = {"note_id": note_id, "message": msg}
        # Add the response into the data section
        action_result.add_data(result)

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
        if_match = param["if_match"]

        # Initialize Pytmv1
        client = self._get_client()

        # Choose enum
        if "new" in status.lower():
            status = pytmv1.InvestigationStatus.NEW
        elif "in_progress" in status.lower():
            status = pytmv1.InvestigationStatus.IN_PROGRESS
        elif "true_positive" in status.lower():
            status = pytmv1.InvestigationStatus.TRUE_POSITIVE
        elif "false_positive" in status.lower():
            status = pytmv1.InvestigationStatus.FALSE_POSITIVE
        elif "benign_true_positive" in status.lower():
            status = pytmv1.InvestigationStatus.BENIGN_TRUE_POSITIVE
        elif "closed" in status.lower():
            status = pytmv1.InvestigationStatus.CLOSED

        # make rest call
        response = client.edit_alert_status(
            alert_id=workbench_id, status=status, if_match=if_match
        )

        if phantom.is_fail(response.result_code):
            return action_result.get_status()

        message = response.result_code
        # Add the response into the data section
        action_result.add_data(message)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_details(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        workbench_id = param["workbench_id"]

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        response = client.get_alert_details(alert_id=workbench_id)

        if phantom.is_fail(response.result_code):
            return action_result.get_status()

        etag = response.response.etag
        alert = response.response.alert.json()

        alert_details = {"etag": etag, "alert": alert}

        # Add the response into the data section
        action_result.add_data(alert_details)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_urls_to_sandbox(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Param setup
        urls = json.loads(param["urls"])

        # Initialize Pytmv1
        client = self._get_client()

        submit_urls_resp = {"submit_urls_resp": []}
        # make rest call
        for i in urls:
            response = client.submit_urls_to_sandbox(i)
            if "error" in response.result_code.lower():
                return response.errors
            else:
                submit_urls_resp["submit_urls_resp"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(submit_urls_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enable_account(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        account_identifiers = json.loads(param["account_identifiers"])

        multi_resp = {"multi_response": []}
        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in account_identifiers:
            response = client.enable_account(
                pytmv1.AccountTask(
                    accountName=i["account_name"],
                    description=i.get("description", "Enable User Account"),
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_disable_account(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        account_identifiers = json.loads(param["account_identifiers"])

        multi_resp: Dict[str, Any] = {"multi_response": []}
        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        for i in account_identifiers:
            response = client.disable_account(
                pytmv1.AccountTask(
                    accountName=i["account_name"],
                    description=i.get("description", "Disable User Account"),
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restore_email_message(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        email_identifiers = json.loads(param["email_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = {"multi_response": []}
        # make rest call
        for i in email_identifiers:
            if i["message_id"].startswith("<") and i["message_id"].endswith(">"):
                response = client.restore_email_message(
                    pytmv1.EmailMessageIdTask(
                        messageId=i["message_id"],
                        description=i.get("description", ""),
                        mailbox=i.get("mailbox", ""),
                    )
                )
            else:
                response = client.restore_email_message(
                    pytmv1.EmailMessageUIdTask(
                        uniqueId=i["message_id"],
                        description=i.get("description", ""),
                    )
                )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sign_out_account(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        account_identifiers = json.loads(param["account_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = {"multi_response": []}

        # make rest call
        for i in account_identifiers:
            response = client.sign_out_account(
                pytmv1.AccountTask(
                    accountName=i["account_name"], description=i.get("description", "")
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_force_password_reset(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        account_identifiers = json.loads(param["account_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = {"multi_response": []}

        # make rest call
        for i in account_identifiers:
            response = client.reset_password_account(
                pytmv1.AccountTask(
                    accountName=i["account_name"], description=i.get("description", "")
                )
            )
            if "error" in response.result_code.lower():
                return response.errors
            else:
                multi_resp["multi_response"].append(
                    response.response.dict().get("items")[0]
                )

        # Add the response into the data section
        action_result.add_data(multi_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sandbox_suspicious_list(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        submit_id = param["submit_id"]
        poll = param["poll"]

        # Optional Params
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.get_sandbox_suspicious_list(
            submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
        )

        if "error" in response.result_code.lower():
            return response.error
        else:
            sandbox_suspicious_list_resp: List[Any] = []
            for i in response.response.dict().get("items"):
                sandbox_suspicious_list_resp.append(json.loads(json.dumps(i)))

        # Create Container
        container = {}
        container["name"] = submit_id
        container["source_data_identifier"] = "File Analysis Report - Suspicious Object"
        container["label"] = "trendmicro"
        try:
            container["severity"] = sandbox_suspicious_list_resp[0][
                "risk_level"
            ].capitalize()
        except Exception:
            container["severity"] = "Medium"
        container["tags"] = "suspiciousObject"
        ret_val, msg, cid = self.save_container(container)

        artifacts = []
        for i in sandbox_suspicious_list_resp[0]:
            artifacts_d = {}
            artifacts_d["name"] = "Artifact of {}".format(submit_id)
            artifacts_d[
                "source_data_identifier"
            ] = "File Analysis Report - Suspicious Object"
            artifacts_d["label"] = "trendmicro"
            artifacts_d["container_id"] = cid
            artifacts_d["cef"] = i
            artifacts.append(artifacts_d)
        ret_val, msg, cid = self.save_artifacts(artifacts)
        self.save_progress("Suspicious Object added to Container")

        # Add the response into the data section
        action_result.add_data(sandbox_suspicious_list_resp)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sandbox_analysis_result(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        report_id = param["report_id"]
        poll = param["poll"]

        # Optional Params
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.get_sandbox_analysis_result(
            submit_id=report_id,
            poll=poll,
            poll_time_sec=poll_time_sec,
        )

        if phantom.is_fail(response.result_code):
            return action_result.get_status()

        analysis_result = json.loads(response.response.json())

        # Add the response into the data section
        action_result.add_data(analysis_result)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sandbox_investigation_package(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        submit_id = param["submit_id"]
        poll = param["poll"]

        # Optional Params
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest Call
        response = client.download_sandbox_investigation_package(
            submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
        )

        if "error" in response.result_code.lower():
            return response
        else:
            # Make filename with timestamp
            name = "Trend_Micro_Sandbox_Investigation_Package.zip"
            timestamp = time.time()
            date_time = datetime.fromtimestamp(timestamp)
            str_date_time = date_time.strftime("%d_%m_%Y_%H_%M_%S")
            file_name = str_date_time + name

            results = self.file_to_vault(
                response.response.content,
                f"{file_name}",
                self.get_container_id(),
                action_result,
            )

        if phantom.is_fail(response.result_code):
            return action_result.get_status()
        # Add the response into the data section
        try:
            action_result.add_data(results)
        except Exception as e:
            action_result.add_data(response)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_suspicious_list(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        new_suspicions = []
        try:
            client.consume_suspicious_list(
                lambda suspicion: new_suspicions.append(suspicion.dict())
            )
        except Exception as e:
            self.debug_print(
                f"Consume Suspicious List failed with following exception: {e}"
            )
            return e
        # Load json objects to list
        suspicious_objects = []
        for i in new_suspicions:
            i["description"] = "" if not i["description"] else i["description"]
            i = json.dumps(i)
            suspicious_objects.append(json.loads(i))

        # Add the response into the data section
        action_result.add_data(suspicious_objects)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_exception_list(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize Pytmv1
        client = self._get_client()

        # make rest call
        new_exceptions = []
        try:
            client.consume_exception_list(
                lambda exception: new_exceptions.append(exception.dict())
            )
        except Exception as e:
            self.debug_print(
                f"Consume Suspicious List failed with following exception: {e}"
            )
            return e
        # Load json objects to list
        exception_objects = []
        for i in new_exceptions:
            i["description"] = "" if not i["description"] else i["description"]
            i = json.dumps(i)
            exception_objects.append(json.loads(i))

        # Add the response into the data section
        action_result.add_data(exception_objects)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        action_dict = {
            "on_poll": self._handle_on_poll,
            "add_note": self._handle_add_note,
            "status_check": self._handle_status_check,
            "update_status": self._handle_update_status,
            "enable_account": self._handle_enable_account,
            "start_analysis": self._handle_start_analysis,
            "disable_account": self._handle_disable_account,
            "urls_to_sandbox": self._handle_urls_to_sandbox,
            "sign_out_account": self._handle_sign_out_account,
            "add_to_blocklist": self._handle_add_to_blocklist,
            "add_to_exception": self._handle_add_to_exception,
            "test_connectivity": self._handle_test_connectivity,
            "get_endpoint_info": self._handle_get_endpoint_info,
            "quarantine_device": self._handle_quarantine_device,
            "terminate_process": self._handle_terminate_process,
            "add_to_suspicious": self._handle_add_to_suspicious,
            "get_alert_details": self._handle_get_alert_details,
            "forensic_file_info": self._handle_forensic_file_info,
            "get_exception_list": self._handle_get_exception_list,
            "get_suspicious_list": self._handle_get_suspicious_list,
            "unquarantine_device": self._handle_unquarantine_device,
            "force_password_reset": self._handle_force_password_reset,
            "delete_email_message": self._handle_delete_email_message,
            "delete_from_exception": self._handle_delete_from_exception,
            "remove_from_blocklist": self._handle_remove_from_blocklist,
            "collect_forensic_file": self._handle_collect_forensic_file,
            "restore_email_message": self._handle_restore_email_message,
            "delete_from_suspicious": self._handle_delete_from_suspicious,
            "sandbox_analysis_result": self._handle_sandbox_analysis_result,
            "sandbox_suspicious_list": self._handle_sandbox_suspicious_list,
            "download_analysis_report": self._handle_download_analysis_report,
            "quarantine_email_message": self._handle_quarantine_email_message,
            "get_sandbox_submission_status": self._handle_get_sandbox_submission_status,
            "sandbox_investigation_package": self._handle_sandbox_investigation_package,
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
            r2 = requests.post(
                login_url, verify=False, data=data, headers=headers, timeout=30
            )  # nosemgrep
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
