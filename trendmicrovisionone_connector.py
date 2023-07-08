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

import sys
import json
import pytmv1
import requests
from datetime import timezone, datetime
from typing import Any, Callable, List, Dict, Optional, Union, Tuple
from pytmv1 import (
    HostInfo,
    SaeAlert,
    TiAlert,
    Indicator,
    Entity,
    MsData,
    ObjectType,
    InvestigationStatus,
)

# Phantom App imports
from phantom import app as phantom
from phantom.vault import Vault
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TrendMicroVisionOneConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super(TrendMicroVisionOneConnector, self).__init__()

        self._state: Dict[str, Any] = {}
        self.app = "Trend Micro Vision One V3"
        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url: str = ""

        self.supported_actions: Dict[str, Callable] = {
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

    def handle_exception(self, exception: BaseException):
        error_result = ActionResult(self.get_current_param())
        error_result.set_status(phantom.APP_ERROR)
        error_result.add_exception_details(exception)
        self.add_action_result(error_result)

    def _get_client(self) -> pytmv1.Client:
        return pytmv1.client(self.app, self.api_key, self._base_url)

    def _handle_test_connectivity(self, param):
        """
        Makes a call to endpoint to check connectivity.
        Args:
            N/A
        Returns:
            str: Connectivity pass for fail.
        """
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize Pytmv1 client
        client = self._get_client()

        # Make rest call
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
            endpoint(str): endpoint to be queried
            query_op(str): query operator ['and', 'or']
        Returns:
            List[Any]: Returns a list of objects containing information about an endpoint
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        endpoint = param["ip_hostname_mac"]
        query_op = param["query_op"]

        # Initialize pytmv1
        client = self._get_client()

        # Choose QueryOp Enum based on user choice
        if "or" in query_op:
            query_op = pytmv1.QueryOp.OR
        elif "and" in query_op:
            query_op = pytmv1.QueryOp.AND

        new_endpoint_data: List[Any] = []

        # Make rest call
        try:
            client.consume_endpoint_data(
                lambda endpoint_data: new_endpoint_data.append(endpoint_data.json()),
                pytmv1.QueryOp(query_op),
                endpoint,
            )
        except Exception as e:
            raise RuntimeError(
                f"Something went wrong while fetching endpoint data: {e}"
            )
        # Load json objects to list
        endpoint_data_resp: List[Dict[str, Any]] = []
        for i in new_endpoint_data:
            endpoint_data_resp.append(json.loads(i))

        if len(endpoint_data_resp) == 0:
            self.save_progress(
                f"Endpoint lookup failed, please check endpoint name: {endpoint}"
            )
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(endpoint_data_resp)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_device(self, param):
        """
        Action to isolate an endpoint.
        Args:
            endpoint_identifiers(List[Dict[str, str]]): Object containing Endpoint name and (optional) description.
        Returns:
            Dict[str, List[Any]]: Returns a list of objects containing task_id and HTTP status code
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        endpoint_identifiers: List[Dict[str, str]] = json.loads(
            param.get("endpoint_identifiers")
        )

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Make rest call
        for i in endpoint_identifiers:
            response = client.isolate_endpoint(
                pytmv1.EndpointTask(
                    endpoint_name=i["endpoint"],
                    description=i.get("description", "Quarantine Device."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print("Something went wrong, please check endpoint params.")
                raise RuntimeError(f"Error quarantining endpoint: {response.errors}")
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

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
            ID: Returns an ID or None if no ID exists.
        """
        # Fetch the source data identifier
        sdi = self.create_artifact_identifier(alert_id, indicator_id)
        # check if a given artifact exists for in a container
        url = f'{self.get_phantom_base_url()}rest/artifact?_filter_source_data_identifier="{sdi}"&_filter_container_id={container_id}'
        # Make rest call
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

    def _get_existing_container_id_for_sdi(self, sdi: str) -> Optional[int]:
        """
        Fetch container ID if it exists.
        Args:
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert.
        Raises:
            RuntimeError: Raise an error if REST call fails.
        Returns:
            ID: Return the container ID.
        """
        # check if TM workbenchID already exists in Splunk
        url = f'{self.get_phantom_base_url()}rest/container?_filter_source_data_identifier="{sdi}"&_filter_asset={self.get_asset_id()}'
        # Make rest call
        try:
            response = requests.get(url, verify=False, timeout=30)  # nosemgrep
        except Exception as e:
            raise RuntimeError(
                "Encountered an error getting the existing container ID from Phantom."
            ) from e

        # return id or None
        container_data: dict[str, Any] = response.json()
        if "data" not in container_data or len(container_data["data"]) == 0:
            return None
        # This direct access is okay because the values MUST exist otherwise the problem is out of scope.
        return container_data["data"][0]["id"]

    def _get_existing_container_id_for_alert(
        self, alert: Union[SaeAlert, TiAlert]
    ) -> Optional[int]:
        """
        Fetch container ID if it exists.
        Args:
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert.
        Raises:
            RuntimeError: Raise an error if REST call fails.
        Returns:
            ID: Return the container ID.
        """
        return self._get_existing_container_id_for_sdi(alert.id)

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
        existing_container_id: Optional[
            int
        ] = self._get_existing_container_id_for_alert(alert)

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

            existing_container_id = self._get_existing_container_id_for_alert(alert)

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

    def _get_poll_interval(self, param) -> Tuple[str, str]:
        """
        Helper function for *On Poll* action to get poll interval.
        Args:
            starttime(str): starttime string in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC).
            endtime(str): endtime string in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC).
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
            start_time(str): starttime string in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC).
            end_time(str): endtime string in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC).
        Raises:
            RuntimeError: Raise an error if fetching Alerts fails.
        Returns:
            List[Dict[str, Any]]: List containing Alert Objects.
        """

        # Log current action
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        action_result = self.add_action_result(ActionResult(param))

        # Optional Params
        start_time, end_time = self._get_poll_interval(param)

        # Initialize Pytmv1
        client = self._get_client()

        new_alerts: List[Union[SaeAlert, TiAlert]] = []

        # Make rest call
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
            action_result.update_data(serialized_alerts)
            action_result.set_summary(
                {"Number of Events Found": len(serialized_alerts)}
            )

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
            endpoint_identifiers(List[Dict[str, str]]): endpoint name and optional description.
        Returns:
            multi_resp(Dict[str,Any]): Object containing task_id and HTTP status code.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        endpoint_identifiers: List[Dict[str, str]] = json.loads(
            param.get("endpoint_identifiers")
        )

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Make rest call
        for i in endpoint_identifiers:
            response = client.restore_endpoint(
                pytmv1.EndpointTask(
                    endpoint_name=i["endpoint"],
                    description=i.get("description", "Restore Device."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print("Something went wrong, please check endpoint params.")
                raise RuntimeError(f"Error restoring endpoint: {response.errors}")
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_status_check(self, param):
        """
        Action to check the status of a task based on task_id.
        Args:
            task_id(str): Unique numeric string that identifies a response task.
            poll(str): 	If script should wait until the task is finished before returning the result (disabled by default)
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

        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong, please check task_id.")
            raise RuntimeError(
                f"Error fetching task status for task {task_id}. Result Code: {response.error}"
            )
        assert response.response is not None
        action_result.add_data(response.response.dict())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_to_blocklist(self, param):
        """
        Action to add item to block list.
        Args:
            block_objects(List[Dict[str, str]]): Object object made up of type, value and description.
        Returns:
            multi_resp: Object containing task_id and https status code.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        block_objects: List[Dict[str, Any]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Choose Enum
        for i in block_objects:
            obj_type = i["object_type"].upper()
            if obj_type in ObjectType.__members__:
                i["object_type"] = ObjectType[obj_type]
            else:
                self.debug_print("Something went wrong, please check object type.")
                raise RuntimeError(f"Please check object type: {i['object_type']}")

        # Make rest call
        for i in block_objects:
            response = client.add_to_block_list(
                pytmv1.ObjectTask(
                    object_type=i["object_type"],
                    object_value=i["object_value"],
                    description=i.get("description", "Add To Blocklist."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print("Something went wrong, please input params.")
                raise RuntimeError(
                    f"Error while adding to block list: {response.errors}"
                )
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_from_blocklist(self, param):
        """
        Remove an item from block list.
        Args:
            block_objects(List[Dict[str, str]]): Object containing type, value and (optional) description.
        Returns:
            multi_resp: Object containing task_id and https status code.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        block_objects: List[Dict[str, str]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Choose Enum
        for i in block_objects:
            obj_type = i["object_type"].upper()
            if obj_type in ObjectType.__members__:
                i["object_type"] = ObjectType[obj_type]
            else:
                self.debug_print("Something went wrong, please check object type.")
                raise RuntimeError(f"Please check object type: {i['object_type']}")

        # Make rest call
        for i in block_objects:
            response = client.remove_from_block_list(
                pytmv1.ObjectTask(
                    object_type=i["object_type"],  # type: ignore
                    object_value=i["object_value"],
                    description=i.get("description", "Remove From Blocklist."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print("Something went wrong, please input params.")
                raise RuntimeError(
                    f"Error while removing from block list: {response.errors}"
                )
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_email_message(self, param):
        """
        Action to quarantine an email using the mailBox and messageId or uniqueId
        Args:
            email_identifiers(List[Dict[str, str]]): Object containing mailBox/messageId and optional description
            or uniqueId and optional description.
        Returns:
            multi_resp(List[Dict[str, Any]]): Object containing task_id and HTTP status code.
        """
        # send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        email_identifiers: List[Dict[str, str]] = json.loads(param["email_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Make rest call
        for i in email_identifiers:
            if i["message_id"].startswith("<") and i["message_id"].endswith(">"):
                response = client.quarantine_email_message(
                    pytmv1.EmailMessageIdTask(
                        message_id=i["message_id"],
                        description=i.get("description", "Quarantine Email Message."),
                        mail_box=i.get("mailbox", ""),
                    )
                )
            else:
                response = client.quarantine_email_message(
                    pytmv1.EmailMessageUIdTask(
                        unique_id=i["message_id"],
                        description=i.get("description", "Quarantine Email Message."),
                    )
                )
            if "error" in response.result_code.lower():
                self.debug_print(
                    "Something went wrong, please check email identifiers."
                )
                raise RuntimeError(f"Error while quarantining email: {response.errors}")
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_email_message(self, param):
        """
        Action to delete an email using the mailBox and messageId or uniqueId.
        Args:
            email_identifiers(List[Dict[str, str]]): Object containing mailBox/messageId and optional description
            or uniqueId and optional description.
        Returns:
            multi_resp(Dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        email_identifiers: List[Dict[str, str]] = json.loads(param["email_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Make rest call
        for i in email_identifiers:
            if i["message_id"].startswith("<") and i["message_id"].endswith(">"):
                response = client.delete_email_message(
                    pytmv1.EmailMessageIdTask(
                        message_id=i["message_id"],
                        description=i.get("description", "Delete Email Message."),
                        mail_box=i.get("mailbox", ""),
                    )
                )
            else:
                response = client.delete_email_message(
                    pytmv1.EmailMessageUIdTask(
                        unique_id=i["message_id"],
                        description=i.get("description", "Delete Email Message."),
                    )
                )
            if "error" in response.result_code.lower():
                self.debug_print(
                    "Something went wrong, please check email identifiers."
                )
                raise RuntimeError(f"Error while deleting email: {response.errors}")
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_terminate_process(self, param):
        """
        Terminates a process that is running on one or more endpoints.
        Note: You can specify either the computer name ("endpointName") or the GUID of the installed agent program ("agentGuid").
        Args:
            process_identifiers(List[Dict[str, str]]): Object containing mailBox/messageId and optional description
            or uniqueId and optional description.
        Returns:
            multi_resp(Dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        process_identifiers: List[Dict[str, str]] = json.loads(
            param["process_identifiers"]
        )

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Make rest call
        for i in process_identifiers:
            response = client.terminate_process(
                pytmv1.ProcessTask(
                    endpoint_name=i["endpoint"],
                    file_sha1=i["file_sha1"],
                    description=i.get("description", "Terminate Process."),
                    file_name=i.get("filename", ""),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print(
                    "Something went wrong, please check process identifiers."
                )
                raise RuntimeError(
                    f"Error while terminating process: {response.errors}"
                )
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def exception_list_count(self) -> int:
        """Gets the count of objects present in exception list"""
        # Initialize Pytmv1
        client = self._get_client()

        new_exceptions: List[Dict[str, Any]] = []
        try:
            client.consume_exception_list(
                lambda exception: new_exceptions.append(exception.dict())
            )
        except Exception as e:
            self.debug_print("Consume Exception List failed with following exception:")
            raise RuntimeError("Error while fetching exception list count.") from e

        # Load json objects to list
        exception_objects: List[Dict[str, Any]] = []
        for i in new_exceptions:
            i["description"] = "" if not i["description"] else i["description"]
            i = json.dumps(i)
            exception_objects.append(json.loads(i))
        exception_count = len(exception_objects)
        return exception_count

    def _handle_add_to_exception(self, param):
        """
        Adds domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs to the Exception List.
        Args:
            block_objects(List[Dict[str, str]]): List of objects containing type, value and optional description.
        Returns:
            multi_resp(Dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        block_objects: List[Dict[str, str]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Choose Enum
        for i in block_objects:
            obj_type = i["object_type"].upper()
            if obj_type in ObjectType.__members__:
                i["object_type"] = ObjectType[obj_type]
            else:
                raise RuntimeError(f"Please check object type: {i['object_type']}")

        # Make rest call
        for i in block_objects:
            response = client.add_to_exception_list(
                pytmv1.ObjectTask(
                    object_type=i["object_type"],  # type: ignore
                    object_value=i["object_value"],
                    description=i.get("description", "Add To Exception List."),
                )
            )
            if "error" in response.result_code.lower():
                raise RuntimeError(
                    f"Error while adding to exception list: {response.errors}"
                )
            assert response.response is not None
            items = response.response.dict().get("items", [])[0]
            items["task_id"] = (
                "None" if items.get("task_id") is None else items["task_id"]
            )
            multi_resp.append(items)

        # Get total exception list count
        total_exception_count = self.exception_list_count()
        # Add the response into the data section
        action_result.add_data(
            {"multi_response": multi_resp, "total_count": total_exception_count}
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_from_exception(self, param):
        """
        Deletes the specified objects from the Exception List.
        Args:
            block_objects(List[Dict[str, str]]): List of objects containing type, value and optional description.
        Returns:
            multi_resp(Dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        block_objects: List[Dict[str, str]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Choose Enum
        for i in block_objects:
            obj_type = i["object_type"].upper()
            if obj_type in ObjectType.__members__:
                i["object_type"] = ObjectType[obj_type]
            else:
                raise RuntimeError(f"Please check object type: {i['object_type']}")

        # Make rest call
        for i in block_objects:
            response = client.remove_from_exception_list(
                pytmv1.ObjectTask(
                    object_type=i["object_type"], object_value=i["object_value"]  # type: ignore
                )
            )
            if "error" in response.result_code.lower():
                raise RuntimeError(
                    f"Error while removing from exception list: {response.errors}"
                )
            assert response.response is not None
            items = response.response.dict().get("items", [])[0]
            items["task_id"] = (
                "None" if items.get("task_id") is None else items["task_id"]
            )
            multi_resp.append(items)

        total_exception_count = self.exception_list_count()
        # Add the response into the data section
        action_result.add_data(
            {"multi_response": multi_resp, "total_count": total_exception_count}
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def suspicious_list_count(self) -> int:
        """Gets the count of objects present in suspicious list"""
        # Initialize Pytmv1
        client = self._get_client()

        new_suspicious: List[Dict[str, Any]] = []

        try:
            client.consume_suspicious_list(
                lambda suspicious: new_suspicious.append(suspicious.dict())
            )
        except Exception as e:
            self.debug_print("Consume Suspicious List failed with following exception:")
            raise RuntimeError("Error while fetching suspicious list count.") from e
        # Load json objects to list
        suspicious_objects: List[Dict[str, Any]] = []
        for i in new_suspicious:
            i["description"] = "" if not i["description"] else i["description"]
            i = json.dumps(i)
            suspicious_objects.append(json.loads(i))
        suspicious_count = len(suspicious_objects)
        return suspicious_count

    def _handle_add_to_suspicious(self, param):
        """
        Adds information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs to the Suspicious Object List.
        Notes:
        You can add up to 10,000 suspicious objects of each type to the list.
        If you try to add elements after reaching the limit of each category, the system automatically deletes
        the objects with the closest expiration date.
        Args:
            block_objects(List[Dict[str, str]]): List of objects containing type, value and optional description.
        Returns:
            multi_resp(Dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        block_objects: List[Dict[str, Any]] = json.loads(param.get("block_objects"))

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Choose Enum
        for i in block_objects:
            obj_type = i["object_type"].upper()
            if obj_type in ObjectType.__members__:
                i["object_type"] = ObjectType[obj_type]
            else:
                raise RuntimeError(f"Please check object type: {i['object_type']}")

        for i in block_objects:
            response = client.add_to_suspicious_list(
                pytmv1.SuspiciousObjectTask(
                    object_type=i["object_type"],
                    object_value=i["object_value"],
                    scan_action=i.get("scan_action", "block"),
                    risk_level=i.get("risk_level", "medium"),
                    days_to_expiration=i.get("expiry_days", 30),
                )
            )
            if "error" in response.result_code.lower():
                raise RuntimeError(
                    f"Error while adding to suspicious list: {response.errors}"
                )
            assert response.response is not None
            items = response.response.dict().get("items", [])[0]
            items["task_id"] = (
                "None" if items.get("task_id") is None else items["task_id"]
            )
            multi_resp.append(items)

        # Get suspicious list count
        total_suspicious_count = self.suspicious_list_count()
        # Add the response into the data section
        action_result.add_data(
            {"multi_response": multi_resp, "total_count": total_suspicious_count}
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_from_suspicious(self, param):
        """
        Deletes information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses,
        or URLs from the Suspicious Object List.
        Args:
            block_objects(List[Dict[str, str]]): List of objects containing type, value and optional description.
        Returns:
            multi_resp(Dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        block_objects: List[Dict[str, str]] = json.loads(param.get("block_objects"))

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp: List[MsData] = []

        # Choose Enum
        for i in block_objects:
            obj_type = i["object_type"].upper()
            if obj_type in ObjectType.__members__:
                i["object_type"] = ObjectType[obj_type]
            else:
                raise RuntimeError(f"Please check object type: {i['object_type']}")

        # Make rest call
        for i in block_objects:
            response = client.remove_from_suspicious_list(
                pytmv1.ObjectTask(
                    object_type=i["object_type"], object_value=i["object_value"]  # type: ignore
                )
            )
            if "error" in response.result_code.lower():
                raise RuntimeError(
                    f"Error while removing from suspicious list: {response.errors}"
                )
            assert response.response is not None
            items = response.response.dict().get("items", [])[0]
            items["task_id"] = (
                "None" if items.get("task_id") is None else items["task_id"]
            )
            multi_resp.append(items)

        # Get suspicious list count
        total_suspicious_count = self.suspicious_list_count()
        # Add the response into the data section
        action_result.add_data(
            {"multi_response": multi_resp, "total_count": total_suspicious_count}
        )

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
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        task_id = param["task_id"]

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.get_sandbox_submission_status(submit_id=task_id)
        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong, please check task_id.")
            raise RuntimeError(
                f"Error while fetching sandbox submission status: {response.error}"
            )
        assert response.response is not None
        # Add the response into the data section
        action_result.add_data(response.response.dict())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_download_analysis_report(self, param):
        """
        Downloads the analysis results of the specified object as PDF.
        Args:
            submit_id(str): Unique alphanumeric string that identifies the analysis results of a submission.
            poll(str): If script should wait until the task is finished before returning the result (disabled by default).
        Returns:
            file(.pdf): A PDF document containing analysis result for specified object.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        submit_id = param["submit_id"]

        # Optional Params
        poll = param.get("poll", "false")
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.download_sandbox_analysis_result(
            submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
        )

        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong, please check submit_id.")
            raise RuntimeError(
                f"Error while downloading sandbox analysis report: {response.error}"
            )
        assert response.response is not None
        # Default filename
        name = "Trend_Micro_Sandbox_Analysis_Report"
        file_name = f"{name}_{datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.pdf"

        results = Vault.create_attachment(  # noqa: F841
            response.response.content,
            self.get_container_id(),
            file_name,
        )
        # Add the response into the data section
        action_result.add_data({"file_added": file_name})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_collect_forensic_file(self, param):
        """
        Collects a file from one or more endpoints and then sends the files to Trend Vision One in a password-protected archive.
        Note: You can specify either the computer name ("endpointName") or the GUID of the installed agent program ("agentGuid").
        Args:
            collect_files(List[Dict[str, str]]): List of Dict objects containing endpoint and filepath to file to be analyzed.
        Returns:
            Dict[str, List]: List consisting of dict objects containing task_id and HTTP status code.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        collect_files: List[Dict[str, str]] = json.loads(param.get("collect_files"))

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = []

        # Make rest call
        for i in collect_files:
            response = client.collect_file(
                pytmv1.FileTask(
                    endpoint_name=i["endpoint"],
                    file_path=i["file_path"],
                    description=i.get("description", "Collect File."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print("Something went wrong, please check inputs.")
                raise RuntimeError(f"Error while collecting file: {response.errors}")
            else:
                assert response.response is not None
                multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_forensic_file_info(self, param):
        """
        Retrieves an object containing the result of collect forensic file task in JSON format.
        Args:
            task_id(str): Unique numeric string that identifies a response task (e.g. 00000012).
            poll(str): If script should wait until the task is finished before returning the result (disabled by default).
        Returns:
            file_info(Dict[str, Any]): Dict object containing response data for file collected.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        task_id = param["task_id"]

        # Optional Params
        poll = param.get("poll", "false")
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.get_base_task_result(
            task_id=task_id,
            poll=poll,
            poll_time_sec=poll_time_sec,
        )

        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong, please check task_id.")
            raise RuntimeError(
                f"Error fetching forensic file info for task {task_id}. Result Code: {response.error}"
            )
        assert response.response is not None
        file_info = response.response.dict()

        # Add the response into the data section
        action_result.add_data(file_info)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_analysis(self, param):
        """
        Submits a file to the sandbox for analysis.
        Args:
            file_url(str): URL pointing to the file
            file_name(str): Name of the file being submitted.
            document_password(str): Password encoded in Base64 used to decrypt the submitted file sample.
            The maximum password length (without encoding) is 128 bytes.
            archive_password(str): Password encoded in Base64 used to decrypt the submitted archive.
            The maximum password length (without encoding) is 128 bytes.
            arguments(str): Parameter that allows you to specify Base64-encoded command line arguments to run the submitted file.
            The maximum argument length before encoding is 1024 bytes. Arguments are only available for Portable Executable (PE)
            files and script files.
        Returns:
            response(Dict[str, Any]): Response object containing ID for submitted object along with digest values.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        file_url = param["file_url"]
        file_name = param["file_name"]

        # Optional Params
        document_password = param.get("document_pass", "")
        archive_password = param.get("archive_pass", "")
        arguments = param.get("arguments", "None")

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.submit_file_to_sandbox(
            file=file_url,
            file_name=file_name,
            document_password=document_password,
            archive_password=archive_password,
            arguments=arguments,
        )

        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong, please check file_url.")
            raise RuntimeError(
                f"Error submitting file to sandbox for analysis. Result Code: {response.error}"
            )

        # Add the response into the data section
        assert response.response is not None
        action_result.add_data(response.response.dict())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_note(self, param):
        """
        Adds a note to the specified Workbench alert
        Args:
            workbench_id(str): Numeric string that identifies a Workbench alert (e.g. WB-14-20190709-00003).
            content(str): Content of the note to be added to Workbench Alert.
        Returns:
            result(Dict[str, str]): Contains the ID for newly created not and success message.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        workbench_id = param["workbench_id"]
        content = param["content"]

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.add_alert_note(alert_id=workbench_id, note=content)

        if "error" in response.result_code.lower():
            self.debug_print(
                "Something went wrong, please check workbench_id and content."
            )
            raise RuntimeError(
                f"Error adding note to workbench {workbench_id}. Result Code: {response.error}"
            )

        assert response.response is not None
        location = response.response.location
        note_id = location.split("/")[-1]
        msg = "success"
        result = {"note_id": note_id, "message": msg}
        # Add the response into the data section
        action_result.add_data(result)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_status(self, param):
        """
        Modifies the status of an alert or investigation triggered in Workbench.
        Args:
            workbench_id(str): Workbench alert ID (e.g. WB-14-20190709-00003)
            status(str): Status to be updated ("New" "In Progress" "True Positive" "False Positive" "Benign True Positive" "Closed").
            if_match(str): Target resource will be updated only if it matches ETag of the target one (e.g. "d41d8cd98f00b204e9800998ecf8427e").
        Returns:
            message(str): Success or Failure.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        workbench_id = param["workbench_id"]
        status = param["status"]
        if_match = param["if_match"]

        # Initialize Pytmv1
        client = self._get_client()

        # Choose Status Enum
        sts = status.upper()
        if sts in InvestigationStatus.__members__:
            status = InvestigationStatus[sts]
        else:
            self.debug_print("Something went wrong, please check input params.")
            raise RuntimeError(f"Please check status: {status}")

        # Make rest call
        response = client.edit_alert_status(
            alert_id=workbench_id, status=status, if_match=if_match
        )

        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong while updating alert status.")
            raise RuntimeError(
                f"Error updating alert status for {workbench_id}. Result Code: {response.error}"
            )

        message = response.result_code
        # Add the response into the data section
        action_result.add_data(message)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_details(self, param):
        """
        Displays information about the specified alert.
        Args:
            workbench_id(str): ID for a specific workbench alert (e.g. WB-14-20190709-00003).
        Returns:
            alert_details (Dict[str, Any]): Returns an Alert (SaeAlert or TiAlert) and
            ETag (an identifier for a specific version of a Workbench alert resource).
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        workbench_id = param["workbench_id"]

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.get_alert_details(alert_id=workbench_id)

        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong, please check workbench_id.")
            raise RuntimeError(
                f"Error fetching alert details for {workbench_id}. Result Code: {response.error}"
            )

        assert response.response is not None
        etag = response.response.etag
        alert = response.response.alert.json()

        alert_details: Dict[str, Any] = {"etag": etag, "alert": alert}

        # Add the response into the data section
        action_result.add_data(alert_details)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_urls_to_sandbox(self, param):
        """
        You can submit a maximum of 10 URLs per request.
        Args:
            urls(List[str]): A list of URLS that will be sent to sandbox for analysis.
        Returns:
            submit_urls_resp (List[Dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        urls: List[str] = json.loads(param["urls"])

        # Initialize Pytmv1
        client = self._get_client()

        submit_urls_resp = []

        # Make rest call
        for i in urls:
            response = client.submit_urls_to_sandbox(i)
            if "error" in response.result_code.lower():
                self.debug_print("Something went wrong, please check urls.")
                raise RuntimeError(
                    f"Error while submitting URLs to sandbox: {response.errors}"
                )
            assert response.response is not None
            submit_urls_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data(
            {"submit_urls_resp": [item.dict() for item in submit_urls_resp]}
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enable_account(self, param):
        """
        Allows the user to sign in to new application and browser sessions.
        Args:
            account_identifiers(List[Dict]): Object containing the accountName and optional description.
        Returns:
            multi_response(List[Dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        account_identifiers: List[Dict[str, str]] = json.loads(
            param["account_identifiers"]
        )

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = []

        # Make rest call
        for i in account_identifiers:
            response = client.enable_account(
                pytmv1.AccountTask(
                    account_name=i["account_name"],
                    description=i.get("description", "Enable User Account."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print(
                    "Something went wrong, please check account identifiers."
                )
                raise RuntimeError(f"Error while enabling account: {response.errors}")
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_disable_account(self, param):
        """
        Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session.
        Args:
            account_identifiers(List[Dict]): Object containing the accountName and optional description.
        Returns:
            multi_response(List[Dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        account_identifiers: List[Dict[str, str]] = json.loads(
            param["account_identifiers"]
        )

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = []

        # Make rest call
        for i in account_identifiers:
            response = client.disable_account(
                pytmv1.AccountTask(
                    account_name=i["account_name"],
                    description=i.get("description", "Disable User Account."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print(
                    "Something went wrong, please check account identifiers."
                )
                raise RuntimeError(
                    f"Error while disabling user account: {response.errors}"
                )
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restore_email_message(self, param):
        """
        Restore quarantined email messages.
        Args:
            email_identifiers(Dict): Object containing the messageId,mailBox and optional description.
            The action can also be run using the message uniqueId and optional description.
        Returns:
            multi_response(List[Dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        email_identifiers: List[Dict[str, str]] = json.loads(param["email_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = []

        # Make rest call
        for i in email_identifiers:
            if i["message_id"].startswith("<") and i["message_id"].endswith(">"):
                response = client.restore_email_message(
                    pytmv1.EmailMessageIdTask(
                        message_id=i["message_id"],
                        description=i.get("description", "Restore Email Message."),
                        mail_box=i.get("mailbox", ""),
                    )
                )
            else:
                response = client.restore_email_message(
                    pytmv1.EmailMessageUIdTask(
                        unique_id=i["message_id"],
                        description=i.get("description", "Restore Email Message."),
                    )
                )
            if "error" in response.result_code.lower():
                self.debug_print(
                    "Something went wrong, please check email identifiers."
                )
                raise RuntimeError(
                    f"Error while restoring email message: {response.errors}"
                )
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sign_out_account(self, param):
        """
        Signs the user out of all active application and browser sessions.
        Args:
            account_identifiers(List[Dict]): Object containing the accountName and optional description.
        Returns:
            multi_response(List[Dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        account_identifiers: List[Dict[str, str]] = json.loads(
            param["account_identifiers"]
        )

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = []

        # Make rest call
        for i in account_identifiers:
            response = client.sign_out_account(
                pytmv1.AccountTask(
                    account_name=i["account_name"],
                    description=i.get("description", "Sign Out Account."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print(
                    "Something went wrong, please check account identifiers."
                )
                raise RuntimeError(
                    f"Error while signing out user account: {response.errors}"
                )
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_force_password_reset(self, param):
        """
        Signs the user out of all active application and browser sessions, and forces
        the user to create a new password during the next sign-in attempt.
        Args:
            account_identifiers(List[Dict]): Object containing the accountName and optional description.
        Returns:
            multi_response(List[Dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        account_identifiers: List[Dict[str, str]] = json.loads(
            param["account_identifiers"]
        )

        # Initialize Pytmv1
        client = self._get_client()

        multi_resp = []

        # Make rest call
        for i in account_identifiers:
            response = client.reset_password_account(
                pytmv1.AccountTask(
                    account_name=i["account_name"],
                    description=i.get("description", "Force Password Reset."),
                )
            )
            if "error" in response.result_code.lower():
                self.debug_print(
                    "Something went wrong, please check account identifiers."
                )
                raise RuntimeError(
                    f"Error while resetting user account password: {response.errors}"
                )
            assert response.response is not None
            multi_resp.append(response.response.items[0])

        # Add the response into the data section
        action_result.add_data({"multi_response": [item.dict() for item in multi_resp]})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sandbox_suspicious_list(self, param):
        """
        Downloads the suspicious object list associated to the specified object
        Note: Suspicious Object Lists are only available for objects with a high risk level
        Args:
            submit_id(str): Unique alphanumeric string that identifies the analysis result of a submission.
            poll(str): If script should wait until the task is finished before returning the result (disabled by default).
        Returns:
            sandbox_suspicious_list_resp(List[Dict]): Array response for suspicious object found.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        submit_id = param["submit_id"]

        # Optional Params
        poll = param.get("poll", "false")
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        sandbox_suspicious_list_resp = []
        # Make rest call
        response = client.get_sandbox_suspicious_list(
            submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
        )

        if "error" in response.result_code.lower():
            raise RuntimeError(
                f"Error while fetching sandbox suspicious list: {response.error}"
            )
        assert response.response is not None
        for i in response.response.dict().get("items", []):
            sandbox_suspicious_list_resp.append(json.loads(json.dumps(i)))

        # Create Container
        container = {}
        container["name"] = submit_id
        container["source_data_identifier"] = "File Analysis Report - Suspicious Object"
        container["label"] = "trendmicro"
        container["tags"] = "suspiciousObject"

        if len(sandbox_suspicious_list_resp) > 0:
            suspicious_object: dict[str, Any] = sandbox_suspicious_list_resp[0]

            container["severity"] = suspicious_object.get(
                "risk_level", "Medium"
            ).capitalize()
        else:
            container["severity"] = "Medium"

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
        """
        Displays the analysis results of the specified object in the sandbox.
        Args:
            report_id(str): report_id of the sandbox submission retrieved from the sandbox-submission-status command.
        Returns:
            Dict: Object containing analysis results for specified ID.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        report_id = param["report_id"]

        # Optional Params
        poll = param.get("poll", "false")
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.get_sandbox_analysis_result(
            submit_id=report_id,
            poll=poll,
            poll_time_sec=poll_time_sec,
        )

        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong, please check report_id.")
            raise RuntimeError(
                f"Error fetching sandbox analysis result: {response.error}"
            )
        assert response.response is not None
        analysis_result = json.loads(response.response.json())

        # Add the response into the data section
        action_result.add_data(analysis_result)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sandbox_investigation_package(self, param):
        """
        Downloads the Investigation Package of the specified object sent to sandbox for analysis.
        Args:
            submit_id(str): Unique alphanumeric string that identifies the analysis results of a submission.
            poll(str): If script should wait until the task is finished before returning the result (disabled by default)
        Returns:
            file(.zip): Investigation package for the specified object.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        submit_id = param["submit_id"]

        # Optional Params
        poll = param.get("poll", "false")
        poll_time_sec = param.get("poll_time_sec", 0)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.download_sandbox_investigation_package(
            submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
        )

        if "error" in response.result_code.lower():
            self.debug_print("Something went wrong, please check submit_id.")
            raise RuntimeError(
                f"Error while downloading investigation package: {response.error}"
            )
        assert response.response is not None
        # Make filename with timestamp
        name = "Trend_Micro_Sandbox_Investigation_Package"
        file_name = f"{name}_{datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.zip"

        results = Vault.create_attachment(  # noqa: F841
            response.response.content,
            self.get_container_id(),
            file_name,
        )
        # Add the response into the data section
        action_result.add_data({"file_added": file_name})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_suspicious_list(self, param):
        """
        Fetch items in the suspicious list.
        Returns:
            List: List of suspicious items.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize Pytmv1
        client = self._get_client()

        new_suspicions: List[Dict[str, Any]] = []

        # Make rest call
        try:
            client.consume_suspicious_list(
                lambda suspicion: new_suspicions.append(suspicion.dict())
            )
        except Exception as e:
            self.debug_print(
                f"Consume Suspicious List failed with following exception: {e}"
            )
            raise e
        # Load json objects to list
        suspicious_objects: List[Dict[str, Any]] = []
        for i in new_suspicions:
            i["description"] = "" if not i["description"] else i["description"]
            i = json.dumps(i)
            suspicious_objects.append(json.loads(i))

        # Add the response into the data section
        action_result.add_data(suspicious_objects)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_exception_list(self, param):
        """
        Fetch items in the exception list.
        Returns:
            List: Items in exceptions list.
        """
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initialize Pytmv1
        client = self._get_client()

        new_exceptions: List[Dict[str, Any]] = []

        # Make rest call
        try:
            client.consume_exception_list(
                lambda exception: new_exceptions.append(exception.dict())
            )
        except Exception as e:
            self.debug_print(
                f"Consume Suspicious List failed with following exception: {e}"
            )
            raise e
        # Load json objects to list
        exception_objects: List[Dict[str, Any]] = []
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
        action_handler: Optional[Callable] = self.supported_actions.get(action_id)

        if action_handler is None:
            raise ValueError("Action requested ({}) was not found".format(action_id))

        action_handler(param)

        return phantom.APP_SUCCESS

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required Params
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
