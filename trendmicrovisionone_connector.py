# File: trendmicrovisionone_connector.py

# Copyright (c) Trend Micro, 2022-2025

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

# Python 3 Compatibility imports

import json
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar, Union

import pytmv1
import requests


if TYPE_CHECKING:
    from stubs import app as phantom
    from stubs.action_result import ActionResult
    from stubs.base_connector import BaseConnector
else:
    from phantom import app as phantom, vault
    from phantom.action_result import ActionResult
    from phantom.base_connector import BaseConnector
    from phantom.vault import Vault

from pytmv1 import (
    AccountRequest,
    AlertStatus,
    CollectFileRequest,
    CollectFileTaskResp,
    EmailMessageIdRequest,
    EmailMessageUIdRequest,
    EndpointRequest,
    ExceptionObject,
    InvestigationResult,
    ObjectRequest,
    ObjectType,
    ResultCode,
    SaeAlert,
    SuspiciousObject,
    SuspiciousObjectRequest,
    TerminateProcessRequest,
    TiAlert,
)


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TrendMicroVisionOneConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._state: dict[str, Any] = {}
        self.config: dict[str, Any] = {}

        self.app = "Trend Vision One V3"
        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url: str = ""

        self.supported_actions: dict[str, Callable] = {
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
            "check_analysis_status": self._handle_check_analysis_status,
            "delete_from_suspicious": self._handle_delete_from_suspicious,
            "vault_sandbox_analysis": self._handle_vault_sandbox_analysis,
            "sandbox_analysis_result": self._handle_sandbox_analysis_result,
            "sandbox_suspicious_list": self._handle_sandbox_suspicious_list,
            "download_analysis_report": self._handle_download_analysis_report,
            "quarantine_email_message": self._handle_quarantine_email_message,
            "sandbox_investigation_package": self._handle_sandbox_investigation_package,
        }

    def handle_exception(self, exception: BaseException):
        error_result = ActionResult(self.get_current_param())
        error_result.set_status(phantom.APP_ERROR)
        error_result.add_exception_details(exception)
        self.add_action_result(error_result)

    def _get_client(self) -> pytmv1.Client:
        return pytmv1.init(self.app, self.api_key, self._base_url)

    @staticmethod
    def _is_pytmv1_error(result_code: ResultCode) -> bool:
        return result_code == ResultCode.ERROR

    _T = TypeVar("_T")

    @staticmethod
    def unwrap(val: Optional[_T]) -> _T:
        if val is None:
            raise ValueError("Expected non-null value but received None.")
        return val

    @staticmethod
    def _get_ot_enum(obj_type: str) -> ObjectType:
        if not obj_type.upper() in ObjectType.__members__:
            raise RuntimeError(f"Please check object type: {obj_type}")
        return ObjectType[obj_type.upper()]

    @staticmethod
    def get_task_type(action: str) -> Any:
        task_dict: dict[Any, list[str]] = {
            pytmv1.AccountTaskResp: [
                "disableAccount",
                "enableAccount",
                "forceSignOut",
                "resetPassword",
            ],
            pytmv1.BlockListTaskResp: ["block", "restoreBlock"],
            pytmv1.EmailMessageTaskResp: [
                "quarantineMessage",
                "restoreMessage",
                "deleteMessage",
            ],
            pytmv1.EndpointTaskResp: ["isolate", "restoreIsolate"],
            pytmv1.TerminateProcessTaskResp: ["terminateProcess"],
        }

        for key, values in task_dict.items():
            if action in values:
                return key

    def _handle_test_connectivity(self, param):
        """
        Makes a call to endpoint to check connectivity.
        Args:
            N/A
        Returns:
            str: Connectivity pass for fail.
        """
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Initialize Pytmv1 client
        client = self._get_client()

        # Make rest call
        response = client.system.check_connectivity()
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Please check your environment variables.")
            self.save_progress("Test Connectivity Failed. Please check your environment variables.")
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
            list[Any]: Returns a list of objects containing information about an endpoint
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        endpoint = json.loads(param["ip_hostname_mac"])
        query_op = param["query_op"]

        # Initialize pytmv1
        client = self._get_client()

        # Choose QueryOp Enum based on user choice
        if query_op.lower() == "or":
            query_op = pytmv1.QueryOp.OR
        else:
            query_op = pytmv1.QueryOp.AND

        new_endpoint_data: list[Any] = []

        # Make rest call
        try:
            client.endpoint.consume_data(
                lambda endpoint_data: new_endpoint_data.append(endpoint_data),
                query_op,
                **endpoint,
            )
        except Exception as e:
            raise RuntimeError(f"Something went wrong while fetching endpoint data: {e}")
        if len(new_endpoint_data) == 0:
            self.save_progress(f"Endpoint lookup failed, please check endpoint name: {endpoint}")
            return action_result.get_status()
        # Load json objects to list
        for endpoint in new_endpoint_data:
            action_result.add_data(endpoint.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_device(self, param):
        """
        Action to isolate an endpoint.
        Args:
            endpoint_identifiers(list[dict[str, str]]): Object containing Endpoint name and (optional) description.
        Returns:
            dict[str, list[Any]]: Returns a list of objects containing task_id and HTTP status code
        """
        # send progress messages back to the platform
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        endpoint_identifiers: list[dict[str, str]] = json.loads(param["endpoint_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        endpt_tasks: list[EndpointRequest] = []

        # Create endpoint task list
        for endpt in endpoint_identifiers:
            if endpt.get("endpoint"):
                endpt_tasks.append(
                    EndpointRequest(
                        endpoint_name=endpt["endpoint"],
                        description=endpt.get("description", "Quarantine Device"),
                    )
                )
            elif endpt.get("agent_guid"):
                endpt_tasks.append(
                    EndpointRequest(
                        agent_guid=endpt["agent_guid"],
                        description=endpt.get("description", "Quarantine Device"),
                    )  # type: ignore
                )

        # Make rest call
        response = client.endpoint.isolate(*endpt_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check endpoint params.")
            raise RuntimeError(f"Error quarantining endpoint: {response.errors}")

        # Add the response into the data section
        quarantine_endpoint_resp: pytmv1.MultiResp = self.unwrap(response.response)
        for item in quarantine_endpoint_resp.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_device(self, param):
        """
        Action to restore endpoint.
        Args:
            endpoint_identifiers(list[dict[str, str]]): endpoint name and optional description.
        Returns:
            multi_resp(dict[str,Any]): Object containing task_id and HTTP status code.
        """
        # send progress messages back to the platform
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        endpoint_identifiers: list[dict[str, str]] = json.loads(param["endpoint_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        endpt_tasks: list[EndpointRequest] = []

        # Create endpoint task list
        for endpt in endpoint_identifiers:
            if endpt.get("endpoint"):
                endpt_tasks.append(
                    EndpointRequest(
                        endpoint_name=endpt["endpoint"],
                        description=endpt.get("description", "Unquarantine Device"),
                    )
                )
            elif endpt.get("agent_guid"):
                endpt_tasks.append(
                    EndpointRequest(
                        agent_guid=endpt["agent_guid"],
                        description=endpt.get("description", "Unquarantine Device"),
                    )  # type: ignore
                )

        # Make rest call
        response = client.endpoint.restore(*endpt_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check endpoint params.")
            raise RuntimeError(f"Error quarantining endpoint: {response.errors}")

        # Add the response into the data section
        unquarantine_endpoint_resp: pytmv1.MultiResp = self.unwrap(response.response)
        for item in unquarantine_endpoint_resp.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_new_artifact_from_alert(self, container_id: int, alert: Union[SaeAlert, TiAlert]):
        """
        Create a new artifact from alert.
        Args:
            container_id (int): ID that will be used to query for containers
            alert (Union[SaeAlert, TiAlert]): SAEAlert or TiAlert object
        Raises:
            RuntimeError: Raise error if artifact creation encounters a problem
        """
        # if artifacts doesn't already exist, make new artifact bundles
        if self.artifact_exists(container_id, alert.id):
            return

        new_artifact = self._create_artifact_content(container_id, alert)

        ret_val, msg, response = self.save_artifacts([new_artifact])
        if phantom.is_fail(ret_val):
            self.save_progress(f"Error saving artifacts: {msg}")
            raise RuntimeError(f"Error saving artifacts: {[new_artifact]}")

    @staticmethod
    def create_artifact_identifier(alert_id: str) -> str:
        """
        Returns string artifact identifier.
        Args:
            alert_id (str): Alert ID.
        Returns:
            str: Artifact identifier string.
        """
        return f"TM-{alert_id}"

    def _create_artifact_content(self, container_id: int, alert: Union[SaeAlert, TiAlert]):
        """
        Gathers information and adds to artifact.
        Args:
            container_id (int): Container ID.
            alert (Union[SaeAlert, TiAlert]): Type of alert (SaeAlert or TiAlert).
        Returns:
            dict[str, Any]: Artifact object.
        """
        # Use pytmv1 mapper to populate artifact cef
        art_cef = pytmv1.mapper.map_cef(alert)

        return {
            "name": alert.id,
            "label": "ALERT",
            "container_id": container_id,
            "source_data_identifier": self.create_artifact_identifier(alert.id),
            "type": alert.alert_provider,
            "severity": alert.severity.value,
            "start_time": alert.created_date_time,
            "indicators": [ind.model_dump() for ind in alert.indicators],
            "cef": art_cef,
        }

    def _update_container_metadata(self, container_id: int, alert: Union[SaeAlert, TiAlert]):
        """
        Updates an Alert container.
        Args:
            container_id (int): ID for the container.
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert
        Raises:
            RuntimeError: Raise a runtime error if container update fails.
        """
        # update old container
        container_alert_metadata: dict[str, Any] = {
            "data": alert.model_dump(),
            "description": f"{container_id}: {alert.alert_provider.value}",
        }
        try:
            requests.post(
                f"{self.get_phantom_base_url()}rest/container/{container_id}",
                data=json.dumps(container_alert_metadata),
                verify=False,
                timeout=30,
            )  # nosemgrep
        except Exception as e:
            raise RuntimeError("Encountered an error updateding container alert.") from e

    def artifact_exists(self, container_id: int, alert_id: str):
        """
        Makes a rest call to see if the artifact exists or not.
        Args:
            container_id (int): Container ID to filter.
            alert_id (str): Alert ID.
        Returns:
            ID: Returns an ID or None if no ID exists.
        """
        # Fetch the source data identifier
        sdi = self.create_artifact_identifier(alert_id)
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
            raise RuntimeError("Encountered an error getting the existing container ID from Phantom.") from e

        # return id or None
        container_data: dict[str, Any] = response.json()
        if "data" not in container_data or len(container_data["data"]) == 0:
            return None
        # This direct access is okay because the values MUST exist otherwise the problem is out of scope.
        return container_data["data"][0]["id"]

    def _get_existing_container_id_for_alert(self, alert: Union[SaeAlert, TiAlert]) -> Optional[int]:
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

    def _create_new_container_payload(self, alert: Union[SaeAlert, TiAlert]) -> dict[str, Any]:
        """
        Returns information for an Alert
        Args:
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert object.
        Returns:
            dict[str, Any]: All pertinent data used to create container from Alert.
        """
        return {
            "name": alert.model,
            "source_data_identifier": alert.id,
            "label": self.config.get("ingest", {}).get("container_label"),
            "description": alert.description if isinstance(alert, SaeAlert) else "",
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
        existing_container_id: Optional[int] = self._get_existing_container_id_for_alert(alert)

        # If a container ID does not already exist, create a new one first, because the update operation
        # runs regardless of whether the container is new or existing.
        if existing_container_id is None:
            # save new container to Splunk using the alert
            ret_val, msg, cid = self.save_container(self._create_new_container_payload(alert))

            if phantom.is_fail(ret_val):
                self.save_progress(f"Error saving container: {msg}")
                raise RuntimeError(f"Error saving container: {msg} -- CID: {cid}")

            existing_container_id = self._get_existing_container_id_for_alert(alert)

            # Assertion made for type checking. At this point, the container ID will not be None if it was
            # successfully created.
            assert existing_container_id is not None
        return existing_container_id

    def _create_container_artifacts(self, container_id: int, alert: Union[SaeAlert, TiAlert]):
        """
        Create an artifact for a container.
        Args:
            container_id (int): ID for the container.
            alert (Union[SaeAlert, TiAlert]): SaeAlert or TiAlert object.
        """
        # add new artifacts
        self._create_new_artifact_from_alert(container_id, alert)

    def _get_poll_interval(self, param) -> tuple[str, str]:
        """
        Helper function for *On Poll* action to get poll interval.
        Args:
            starttime(str): starttime string in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC).
            endtime(str): endtime string in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC).
        Returns:
            Tuple[datetime, datetime]: start and end datetime.
        """
        # standard time frame for poll interval
        default_end_time = datetime.fromtimestamp(int(datetime.utcnow().timestamp())).isoformat() + "Z"
        start_time: str = param.get("starttime", self._state.get("last_ingestion_time", "2020-06-15T10:00:00Z"))
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
            list[dict[str, Any]]: List containing Alert Objects.
        """

        # Log current action
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(param))

        # Optional Params
        start_time, end_time = self._get_poll_interval(param)

        # Initialize Pytmv1
        client = self._get_client()

        new_alerts: list[Union[SaeAlert, TiAlert]] = []

        # Make rest call
        try:
            client.alert.consume(
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
            serialized_alerts: list[dict[str, Any]] = [item.model_dump() for item in new_alerts]
            action_result.update_data(serialized_alerts)
            action_result.set_summary({"Number of Events Found": len(serialized_alerts)})

            self.save_progress(f"Phantom imported {len(serialized_alerts)} events")

            # remember current timestamp for next run
            self._state["last_ingestion_time"] = end_time

            return action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            self.save_progress(f"Exception = {e!s}")
            raise e

    def _handle_status_check(self, param):
        """
        Action to check the status of a task based on task_id.
        Args:
            task_id(str): Unique numeric string that identifies a response task.
            poll(str): 	If script should wait until the task is finished before returning the result (disabled by default)
        Returns:
            dict[str, int]: object containing task_id and HTTP status code
        """
        # send progress messages back to the platform
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        task_id = param["task_id"]

        # Optional Params
        poll = param.get("poll", "true")
        poll_time_sec = param.get("poll_time_sec", 30)

        # Initialize Pytmv1
        client = self._get_client()

        # Excluded task action list
        excluded_tasks: list[str] = [
            "collectEvidence",
            "collectNetworkAnalysisPackage",
            "isolateForMultiple",
            "restoreIsolateForMultiple",
            "dumpProcessMemory",
            "remoteShell",
            "runInvestigationKit",
            "runCustomScriptForMultiple",
            "runOsquery",
            "runYaraRules",
        ]

        # Make rest call
        response = client.task.get_result(task_id, poll, poll_time_sec)
        # Get task action type
        action = self.unwrap(response.response).action
        if action not in excluded_tasks:
            action_type = self.get_task_type(action)
            # Make task specific call using action_type
            response = client.task.get_result_class(
                task_id=task_id,
                class_=action_type,
                poll=poll,
                poll_time_sec=poll_time_sec,
            )
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check task_id.")
            raise RuntimeError(f"Error fetching task status for task {task_id}. Result Code: {response.error}")
        action_result.add_data(self.unwrap(response.response).model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_to_blocklist(self, param):
        """
        Action to add item to block list.
        Args:
            block_objects(list[dict[str, str]]): Object object made up of type, value and description.
        Returns:
            multi_resp: Object containing task_id and https status code.
        """
        # send progress messages back to the platform
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        block_objects: list[dict[str, Any]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        block_tasks: list[ObjectRequest] = []

        # Create block task list
        for obj in block_objects:
            block_tasks.append(
                ObjectRequest(
                    object_type=self._get_ot_enum(obj["object_type"]),
                    object_value=obj["object_value"],
                    description=obj.get("description", "Add To Blocklist"),
                )
            )

        # Make rest call
        response = client.object.add_block(*block_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please input params.")
            raise RuntimeError(f"Error while adding to block list: {response.errors}")
        add_block_resp_obj: pytmv1.MultiResp = self.unwrap(response.response)

        # Add the response into the data section
        for item in add_block_resp_obj.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_from_blocklist(self, param):
        """
        Remove an item from block list.
        Args:
            block_objects(list[dict[str, str]]): Object containing type, value and (optional) description.
        Returns:
            multi_resp: Object containing task_id and https status code.
        """
        # send progress messages back to the platform
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        block_objects: list[dict[str, str]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        # Create unblock task list
        unblock_tasks: list[ObjectRequest] = []
        for obj in block_objects:
            unblock_tasks.append(
                ObjectRequest(
                    object_type=self._get_ot_enum(obj["object_type"]),
                    object_value=obj["object_value"],
                    description=obj.get("description", "Remove from Blocklist"),
                )
            )

        # Make rest call
        response = client.object.delete_block(*unblock_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please input params.")
            raise RuntimeError(f"Error while removing items from block list: {response.errors}")
        remove_block_resp_obj: pytmv1.MultiResp = self.unwrap(response.response)

        # Add the response into the data section
        for item in remove_block_resp_obj.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_email_message(self, param):
        """
        Action to quarantine an email using the mailBox and messageId or uniqueId
        Args:
            email_identifiers(list[dict[str, str]]): Object containing mailBox/messageId and optional description
            or uniqueId and optional description.
        Returns:
            multi_resp(list[dict[str, Any]]): Object containing task_id and HTTP status code.
        """
        # send progress messages back to the platform
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        email_identifiers: list[dict[str, str]] = json.loads(param["email_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        email_tasks: list[EmailMessageIdRequest | EmailMessageUIdRequest] = []

        # Create email task list
        for email in email_identifiers:
            if email.get("message_id"):
                email_tasks.append(
                    EmailMessageIdRequest(
                        message_id=email["message_id"],
                        description=email.get("description", "Quarantine Email Message."),
                        mail_box=email.get("mailbox", ""),
                    )
                )
            elif email.get("unique_id"):
                email_tasks.append(
                    EmailMessageUIdRequest(
                        unique_id=email["unique_id"],
                        description=email.get("description", "Quarantine Email Message."),
                    )
                )

        # Make rest call
        response = client.email.quarantine(*email_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check email identifiers.")
            raise RuntimeError(f"Error while quarantining email: {response.errors}")
        quarantine_resp: pytmv1.MultiResp = self.unwrap(response.response)

        # Add the response into the data section
        for item in quarantine_resp.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_email_message(self, param):
        """
        Action to delete an email using the mailBox and messageId or uniqueId.
        Args:
            email_identifiers(list[dict[str, str]]): Object containing mailBox/messageId and optional description
            or uniqueId and optional description.
        Returns:
            multi_resp(dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        email_identifiers: list[dict[str, str]] = json.loads(param["email_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        email_tasks: list[EmailMessageIdRequest | EmailMessageUIdRequest] = []

        # Create email task list
        for email in email_identifiers:
            if email.get("message_id"):
                email_tasks.append(
                    EmailMessageIdRequest(
                        message_id=email["message_id"],
                        description=email.get("description", "Delete Email Message."),
                        mail_box=email.get("mailbox", ""),
                    )
                )
            elif email.get("unique_id"):
                email_tasks.append(
                    EmailMessageUIdRequest(
                        unique_id=email["unique_id"],
                        description=email.get("description", "Delete Email Message."),
                    )
                )

        # Make rest call
        response = client.email.delete(*email_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check email identifiers.")
            raise RuntimeError(f"Error while deleting email: {response.errors}")
        delete_resp: pytmv1.MultiResp = self.unwrap(response.response)

        # Add the response into the data section
        for item in delete_resp.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_terminate_process(self, param):
        """
        Terminates a process that is running on one or more endpoints.
        Note: You can specify either the computer name ("endpointName") or the GUID of the installed agent program ("agentGuid").
        Args:
            process_identifiers(list[dict[str, str]]): Object containing mailBox/messageId and optional description
            or uniqueId and optional description.
        Returns:
            multi_resp(dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        process_identifiers: list[dict[str, str]] = json.loads(param["process_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        process_tasks: list[TerminateProcessRequest] = []

        # Create process task list
        for process in process_identifiers:
            if process.get("endpoint"):
                process_tasks.append(
                    TerminateProcessRequest(
                        endpoint_name=process["endpoint"],
                        file_sha1=process["file_sha1"],
                        description=process.get("description", "Terminate Process."),
                        file_name=process.get("filename", ""),
                    )
                )
            elif process.get("agent_guid"):
                process_tasks.append(
                    TerminateProcessRequest(
                        agent_guid=process["agent_guid"],
                        file_sha1=process["file_sha1"],
                        description=process.get("description", "Terminate Process."),
                        file_name=process.get("filename", ""),
                    )  # type: ignore
                )

        # Make rest call
        response = client.endpoint.terminate_process(*process_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check process identifiers.")
            raise RuntimeError(f"Error while terminating process: {response.errors}")
        process_resp: pytmv1.MultiResp = self.unwrap(response.response)

        # Add the response into the data section
        for item in process_resp.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_exception_count(self) -> int:
        """Gets the count of objects present in exception list"""
        # Initialize Pytmv1
        client = self._get_client()

        new_exceptions: list[ExceptionObject] = []

        try:
            client.object.consume_exception(lambda exception: new_exceptions.append(exception))
        except Exception as e:
            self.debug_print("Consume Exception List failed with following exception:")
            raise RuntimeError("Error while adding to exception list.") from e

        return len(new_exceptions)

    def _handle_add_to_exception(self, param: dict[str, Any]):
        """
        Adds domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs to the Exception List.
        Args:
            block_objects(list[dict[str, str]]): List of objects containing type, value and optional description.
        Returns:
            multi_resp(dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        block_objects: list[dict[str, str]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        excp_tasks: list[ObjectRequest] = []

        # Create exception task list
        for obj in block_objects:
            excp_tasks.append(
                ObjectRequest(
                    object_type=self._get_ot_enum(obj["object_type"]),
                    object_value=obj["object_value"],
                    description=obj.get("description", "Add To Exception List."),
                )
            )

        # Make rest call
        response = client.object.add_exception(*excp_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check block objects.")
            raise RuntimeError(f"Error while adding object to exception list: {response.errors}")
        add_excp_resp: pytmv1.MultiResp = self.unwrap(response.response)

        # Get total exception list count
        total_exception_count = self.get_exception_count()
        # Add the response into the data section
        action_result.add_data(
            {
                "multi_response": [item.model_dump() for item in add_excp_resp.items],
                "total_count": total_exception_count,
            }
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_from_exception(self, param):
        """
        Deletes the specified objects from the Exception List.
        Args:
            block_objects(list[dict[str, str]]): List of objects containing type, value and optional description.
        Returns:
            multi_resp(dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        block_objects: list[dict[str, str]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        excp_tasks: list[ObjectRequest] = []

        # Create exception task list
        for obj in block_objects:
            excp_tasks.append(
                ObjectRequest(
                    object_type=self._get_ot_enum(obj["object_type"]),
                    object_value=obj["object_value"],
                )
            )

        # Make rest call
        response = client.object.delete_exception(*excp_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check block objects.")
            raise RuntimeError(f"Error while removing object from exception list: {response.errors}")
        rmv_excp_resp: pytmv1.MultiResp = self.unwrap(response.response)

        # Get total exception list count
        total_exception_count = self.get_exception_count()
        # Add the response into the data section
        action_result.add_data(
            {
                "multi_response": [item.model_dump() for item in rmv_excp_resp.items],
                "total_count": total_exception_count,
            }
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_suspicious_count(self) -> int:
        """Gets the count of objects present in suspicious list"""
        # Initialize Pytmv1
        client = self._get_client()

        new_suspicious: list[SuspiciousObject] = []

        try:
            client.object.consume_suspicious(lambda suspicious: new_suspicious.append(suspicious))
        except Exception as e:
            self.debug_print("Consume Suspicious List failed with following exception:")
            raise RuntimeError("Error while fetching suspicious list count.") from e

        return len(new_suspicious)

    def _handle_add_to_suspicious(self, param):
        """
        Adds information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs to the Suspicious Object List.
        Notes:
        You can add up to 10,000 suspicious objects of each type to the list.
        If you try to add elements after reaching the limit of each category, the system automatically deletes
        the objects with the closest expiration date.
        Args:
            block_objects(list[dict[str, str]]): List of objects containing type, value and optional description.
        Returns:
            multi_resp(dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        block_objects: list[dict[str, Any]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        suspicious_tasks: list[SuspiciousObjectRequest] = []
        # Create suspicious task list
        for block in block_objects:
            suspicious_tasks.append(
                SuspiciousObjectRequest(
                    object_type=self._get_ot_enum(block["object_type"]),
                    object_value=block["object_value"],
                    scan_action=block.get("scan_action", "block"),
                    risk_level=block.get("risk_level", "medium"),
                    days_to_expiration=block.get("expiry_days", 30),
                    description=block.get("description", "Add to suspicious list."),
                )
            )
        # Make rest call
        response = client.object.add_suspicious(*suspicious_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            raise RuntimeError(f"Error while adding to suspicious list: {response.errors}")
        add_sus_resp: pytmv1.MultiResp = self.unwrap(response.response)

        # Get suspicious list count
        total_suspicious_count = self.get_suspicious_count()
        # Add the response into the data section
        action_result.add_data(
            {
                "multi_response": [item.model_dump() for item in add_sus_resp.items],
                "total_count": total_suspicious_count,
            }
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_from_suspicious(self, param):
        """
        Deletes information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses,
        or URLs from the Suspicious Object List.
        Args:
            block_objects(list[dict[str, str]]): List of objects containing type, value and optional description.
        Returns:
            multi_resp(dict[str, List]): Object containing task_id and HTTP status code.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        block_objects: list[dict[str, str]] = json.loads(param["block_objects"])

        # Initialize Pytmv1
        client = self._get_client()

        suspicious_tasks: list[ObjectRequest] = []

        # Create suspicious task list
        for block in block_objects:
            suspicious_tasks.append(
                ObjectRequest(
                    object_type=self._get_ot_enum(block["object_type"]),
                    object_value=block["object_value"],
                )
            )

        # Make rest call
        response = client.object.delete_suspicious(*suspicious_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            raise RuntimeError(f"Error while removing from suspicious list: {response.errors}")
        dlt_sus_resp: pytmv1.MultiResp = self.unwrap(response.response)

        # Get suspicious list count
        total_suspicious_count = self.get_suspicious_count()
        # Add the response into the data section
        action_result.add_data(
            {
                "multi_response": [item.model_dump() for item in dlt_sus_resp.items],
                "total_count": total_suspicious_count,
            }
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_check_analysis_status(self, param):
        """
        Checks the submission status for item(s) sent to sandbox for analysis.
        Args:
            submit_id: The Output ID  generated from Start-Analysis Command.
        Returns:
            dict: Object containing response regarding submission status.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        task_id = param["task_id"]

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.sandbox.get_submission_status(submit_id=task_id)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check task_id.")
            raise RuntimeError(f"Error while fetching sandbox submission status: {response.error}")
        resp_obj: pytmv1.SandboxSubmissionStatusResp = self.unwrap(response.response)
        # Add the response into the data section
        action_result.add_data(resp_obj.model_dump())

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
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        submit_id = param["submit_id"]

        # Optional Params
        poll = param.get("poll", "true")
        poll_time_sec = param.get("poll_time_sec", 30)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.sandbox.download_analysis_result(submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check submit_id.")
            raise RuntimeError(f"Error while downloading sandbox analysis report: {response.error}")
        analysis_resp: pytmv1.BytesResp = self.unwrap(response.response)
        # Extract content value on successful call
        data = analysis_resp.content
        # Default filename
        name = "Trend_Micro_Sandbox_Analysis_Report"
        file_name = f"{name}_{datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.pdf"

        results = Vault.create_attachment(
            data,
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
            collect_files(list[dict[str, str]]): List of dict objects containing endpoint and filepath to file to be analyzed.
        Returns:
            dict[str, List]: List consisting of dict objects containing task_id and HTTP status code.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        collect_files: list[dict[str, str]] = json.loads(param["collect_files"])

        # Initialize Pytmv1
        client = self._get_client()

        # Create file task list
        file_tasks: list[CollectFileRequest] = []

        # Create file task list
        for file in collect_files:
            if file.get("endpoint"):
                file_tasks.append(
                    CollectFileRequest(
                        endpoint_name=file["endpoint"],
                        file_path=file["file_path"],
                        description=file.get("description", "Collect File."),
                    )
                )
            else:
                file_tasks.append(
                    CollectFileRequest(
                        agent_guid=file["agent_guid"],
                        file_path=file["file_path"],
                        description=file.get("description", "Collect File."),
                    )  # type: ignore
                )

        # Make rest call
        response = client.endpoint.collect_file(*file_tasks)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check inputs.")
            raise RuntimeError(f"Error while collecting file: {response.errors}")
        file_resp: pytmv1.MultiResp = self.unwrap(response.response)

        # Add the response into the data section
        for item in file_resp.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_forensic_file_info(self, param):
        """
        Retrieves an object containing the result of collect forensic file task in JSON format.
        Args:
            task_id(str): Unique numeric string that identifies a response task (e.g. 00000012).
            poll(str): If script should wait until the task is finished before returning the result (disabled by default).
        Returns:
            file_info(dict[str, Any]): dict object containing response data for file collected.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        task_id = param["task_id"]

        # Optional Params
        poll = param.get("poll", "true")
        poll_time_sec = param.get("poll_time_sec", 30)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.task.get_result_class(
            task_id=task_id,
            class_=CollectFileTaskResp,
            poll=poll,
            poll_time_sec=poll_time_sec,
        )
        resp_obj: pytmv1.CollectFileTaskResp = self.unwrap(response.response)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check task_id.")
            raise RuntimeError(f"Error fetching forensic file info for task {task_id}. Result Code: {response.error}")
        # Add the response into the data section
        action_result.add_data(resp_obj.model_dump())

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
            response(dict[str, Any]): Response object containing ID for submitted object along with digest values.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        file_url = param["file_url"]
        file_name = param["file_name"]

        # Optional Params
        document_password = param.get("document_pass", "")
        archive_password = param.get("archive_pass", "")
        arguments = param.get("arguments", "")

        # Initialize Pytmv1
        client = self._get_client()

        # Get file contents
        _file = requests.get(file_url, allow_redirects=True, timeout=30)

        # Make rest call
        response = client.sandbox.submit_file(
            file=_file.content,
            file_name=file_name,
            document_password=document_password,
            archive_password=archive_password,
            arguments=arguments,
        )
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check file_url.")
            raise RuntimeError(f"Error submitting file to sandbox for analysis. Result Code: {response.error}")
        sub_file_resp: pytmv1.SubmitFileToSandboxResp = self.unwrap(response.response)
        # Add the response into the data section
        action_result.add_data(sub_file_resp.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_note(self, param):
        """
        Adds a note to the specified Workbench alert
        Args:
            workbench_id(str): Numeric string that identifies a Workbench alert (e.g. WB-14-20190709-00003).
            content(str): Content of the note to be added to Workbench Alert.
        Returns:
            result(dict[str, str]): Contains the ID for newly created not and success message.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        workbench_id = param["workbench_id"]
        content = param["content"]

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.note.create(alert_id=workbench_id, note_content=content)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check workbench_id and content.")
            raise RuntimeError(f"Error adding note to workbench {workbench_id}. Result Code: {response.error}")

        note_resp: pytmv1.AddAlertNoteResp = self.unwrap(response.response)
        # Add the response into the data section
        action_result.add_data(
            {
                "note_id": note_resp.note_id,
                "message": f"Note has been successfully added to {workbench_id}",
            }
        )

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_status(self, param):
        """
        Modifies the status of an alert or investigation triggered in Workbench.
        Args:
            workbench_id(str): Workbench alert ID (e.g. WB-14-20190709-00003)
            status(str): Status to be updated ("New" "In Progress" "True Positive" "False Positive" "Benign True Positive" "Closed").
            if_match(str): Target resource will be updated only if it matches ETag of the target one (e.g. "d41d8cd98f0.....00998ecf8427e").
        Returns:
            message(str): Success or Failure.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        workbench_id = param["workbench_id"]
        status = param["status"]
        inv_result = param["inv_result"]
        if_match = param["if_match"]

        # Initialize Pytmv1
        client = self._get_client()

        # Choose Status Enum
        sts = AlertStatus[status.upper()]
        # Choose Investigation Enum
        inv_res = InvestigationResult[inv_result.upper()]
        # Make rest call
        response = client.alert.update_status(alert_id=workbench_id, status=sts, etag=if_match, inv_result=inv_res)

        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong while updating alert status.")
            raise RuntimeError(f"Error updating alert status for {workbench_id}. Result Code: {response.error}")
        # Add the response into the data section
        action_result.add_data({"message": f"Successfully updated status for {workbench_id} to {status}."})

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_details(self, param):
        """
        Displays information about the specified alert.
        Args:
            workbench_id(str): ID for a specific workbench alert (e.g. WB-14-20190709-00003).
        Returns:
            alert_details (dict[str, Any]): Returns an Alert (SaeAlert or TiAlert) and
            ETag (an identifier for a specific version of a Workbench alert resource).
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        workbench_id = param["workbench_id"]

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.alert.get(alert_id=workbench_id)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check workbench_id.")
            raise RuntimeError(f"Error fetching alert details for {workbench_id}. Result Code: {response.error}")

        etag = self.unwrap(response.response).etag
        alert = self.unwrap(response.response).data.model_dump()

        alert_details: dict[str, Any] = {"etag": etag, "alert": alert}

        # Add the response into the data section
        action_result.add_data(alert_details)

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_urls_to_sandbox(self, param):
        """
        You can submit a maximum of 10 URLs per request.
        Args:
            urls(list[str]): A list of URLS that will be sent to sandbox for analysis.
        Returns:
            submit_urls_resp (list[dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        urls: list[str] = json.loads(param["urls"])

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.sandbox.submit_url(*urls)
        urls_resp: pytmv1.MultiUrlResp = self.unwrap(response.response)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check urls.")
            raise RuntimeError(f"Error while submitting URLs to sandbox: {response.errors}")

        for item in urls_resp.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enable_account(self, param):
        """
        Allows the user to sign in to new application and browser sessions.
        Args:
            account_identifiers(list[dict]): Object containing the accountName and optional description.
        Returns:
            multi_response(list[dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        account_identifiers: list[dict[str, str]] = json.loads(param["account_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        account_tasks: list[AccountRequest] = []

        # Create account task list
        for account in account_identifiers:
            account_tasks.append(
                AccountRequest(
                    account_name=account["account_name"],
                    description=account.get("description", "Enable User Account."),
                )
            )
        # Make rest call
        response = client.account.enable(*account_tasks)
        enable_resp_obj: pytmv1.MultiResp = self.unwrap(response.response)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check account identifiers.")
            raise RuntimeError(f"Error while enabling user account: {response.errors}")

        # Add the response into the data section
        for item in enable_resp_obj.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_disable_account(self, param):
        """
        Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session.
        Args:
            account_identifiers(list[dict]): Object containing the accountName and optional description.
        Returns:
            multi_response(list[dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        account_identifiers: list[dict[str, str]] = json.loads(param["account_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        account_tasks: list[AccountRequest] = []

        # Create account task list
        for account in account_identifiers:
            account_tasks.append(
                AccountRequest(
                    account_name=account["account_name"],
                    description=account.get("description", "Disable User Account."),
                )
            )

        # Make rest call
        response = client.account.disable(*account_tasks)
        disable_resp_obj: pytmv1.MultiResp = self.unwrap(response.response)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check account identifiers.")
            raise RuntimeError(f"Error while disabling user account: {response.errors}")

        # Add the response into the data section
        for item in disable_resp_obj.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restore_email_message(self, param):
        """
        Restore quarantined email messages.
        Args:
            email_identifiers(dict): Object containing the messageId,mailBox and optional description.
            The action can also be run using the message uniqueId and optional description.
        Returns:
            multi_response(list[dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        email_identifiers: list[dict[str, str]] = json.loads(param["email_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        email_tasks: list[EmailMessageIdRequest | EmailMessageUIdRequest] = []

        # Create email task list
        for email in email_identifiers:
            if email.get("message_id"):
                email_tasks.append(
                    EmailMessageIdRequest(
                        message_id=email["message_id"],
                        mail_box=email.get("mailbox", ""),
                        description=email.get("description", "Restore Email Message."),
                    )
                )
            elif email.get("unique_id"):
                email_tasks.append(
                    EmailMessageUIdRequest(
                        unique_id=email["unique_id"],
                        description=email.get("description", "Restore Email Message."),
                    )
                )

        # Make rest call
        response = client.email.restore(*email_tasks)
        quarantine_resp: pytmv1.MultiResp = self.unwrap(response.response)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check email identifiers.")
            raise RuntimeError(f"Error while restoring email: {response.errors}")

        # Add the response into the data section
        for item in quarantine_resp.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sign_out_account(self, param):
        """
        Signs the user out of all active application and browser sessions.
        Args:
            account_identifiers(list[dict]): Object containing the accountName and optional description.
        Returns:
            multi_response(list[dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        account_identifiers: list[dict[str, str]] = json.loads(param["account_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        account_tasks: list[AccountRequest] = []

        # Create account task list
        for account in account_identifiers:
            account_tasks.append(
                AccountRequest(
                    account_name=account["account_name"],
                    description=account.get("description", "Sign Out Account."),
                )
            )
        # Make rest call
        response = client.account.sign_out(*account_tasks)
        resp_obj: pytmv1.MultiResp = self.unwrap(response.response)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check account identifiers.")
            raise RuntimeError(f"Error while signing out user account: {response.errors}")

        # Add the response into the data section
        for item in resp_obj.items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_force_password_reset(self, param):
        """
        Signs the user out of all active application and browser sessions, and forces
        the user to create a new password during the next sign-in attempt.
        Args:
            account_identifiers(list[dict]): Object containing the accountName and optional description.
        Returns:
            multi_response(list[dict]): Object containing task_id and http status code for the action call.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        account_identifiers: list[dict[str, str]] = json.loads(param["account_identifiers"])

        # Initialize Pytmv1
        client = self._get_client()

        account_tasks: list[AccountRequest] = []

        # Create account task list
        for account in account_identifiers:
            account_tasks.append(
                AccountRequest(
                    account_name=account["account_name"],
                    description=account.get("description", "Force Password Reset."),
                )
            )

        # Make rest call
        response = client.account.reset(*account_tasks)
        resp_obj: pytmv1.MultiResp = self.unwrap(response.response)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check account identifiers.")
            raise RuntimeError(f"Error while resetting user account password: {response.errors}")

        # Add the response into the data section
        for item in resp_obj.items:
            action_result.add_data(item.model_dump())

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
            sandbox_suspicious_list_resp(list[dict]): Array response for suspicious object found.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        submit_id = param["submit_id"]

        # Optional Params
        poll = param.get("poll", "true")
        poll_time_sec = param.get("poll_time_sec", 30)

        # Initialize Pytmv1
        client = self._get_client()

        sandbox_suspicious_list_resp: list[dict[str, Any]] = []
        # Make rest call
        response = client.sandbox.list_suspicious(submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec)
        sus_list_resp: pytmv1.ListSandboxSuspiciousResp = self.unwrap(response.response)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            raise RuntimeError(f"Error while fetching sandbox suspicious list: {response.error}")
        for item in sus_list_resp.items:
            sandbox_suspicious_list_resp.append(item.model_dump())

        # Create Container
        container = {
            "name": submit_id,
            "source_data_identifier": "File Analysis Report - Suspicious Object",
            "label": "trendmicro",
            "tags": "suspiciousObject",
            "severity": sandbox_suspicious_list_resp[0]["risk_level"].capitalize(),
        }

        ret_val, msg, cid = self.save_container(container)

        artifacts: list[Any] = []
        for sus_obj in sandbox_suspicious_list_resp:
            artifacts_d = {
                "name": f"Artifact of {submit_id}",
                "source_data_identifier": "File Analysis Report - Suspicious Object",
                "label": "trendmicro",
                "container_id": cid,
                "cef": sus_obj,
            }
            artifacts.append(artifacts_d)
        ret_val, msg, cid = self.save_artifacts(artifacts)
        self.save_progress("Suspicious Object added to Container")

        # Add the response into the data section
        for item in self.unwrap(response.response).items:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_sandbox_analysis_result(self, param):
        """
        Displays the analysis results of the specified object in the sandbox.
        Args:
            report_id(str): report_id of the sandbox submission retrieved from the sandbox-submission-status command.
        Returns:
            dict: Object containing analysis results for specified ID.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        report_id = param["report_id"]

        # Optional Params
        poll = param.get("poll", "true")
        poll_time_sec = param.get("poll_time_sec", 30)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.sandbox.get_analysis_result(
            submit_id=report_id,
            poll=poll,
            poll_time_sec=poll_time_sec,
        )
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check report_id.")
            raise RuntimeError(f"Error fetching sandbox analysis result: {response.error}")

        # Add the response into the data section
        action_result.add_data(self.unwrap(response.response).model_dump())

        # Return success
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
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Required Params
        submit_id = param["submit_id"]

        # Optional Params
        poll = param.get("poll", "true")
        poll_time_sec = param.get("poll_time_sec", 30)

        # Initialize Pytmv1
        client = self._get_client()

        # Make rest call
        response = client.sandbox.download_investigation_package(submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec)
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print("Something went wrong, please check submit_id.")
            raise RuntimeError(f"Error while downloading investigation package: {response.error}")
        investigation_resp: pytmv1.BytesResp = self.unwrap(response.response)
        # Make filename with timestamp
        name = "Trend_Micro_Sandbox_Investigation_Package"
        file_name = f"{name}_{datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.zip"

        results = Vault.create_attachment(
            investigation_resp.content,
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
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Initialize Pytmv1
        client = self._get_client()

        new_suspicions: list[SuspiciousObject] = []

        # Make rest call
        try:
            client.object.consume_suspicious(lambda suspicion: new_suspicions.append(suspicion))
        except Exception as e:
            self.debug_print(f"Consume Suspicious List failed with following exception: {e}")
            raise e

        # Add the response into the data section
        for item in new_suspicions:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_exception_list(self, param):
        """
        Fetch items in the exception list.
        Returns:
            List: Items in exceptions list.
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # Initialize Pytmv1
        client = self._get_client()

        new_exceptions: list[ExceptionObject] = []

        # Make rest call
        try:
            client.object.consume_exception(lambda exception: new_exceptions.append(exception))
        except Exception as e:
            self.debug_print(f"Consume Suspicious List failed with following exception: {e}")
            raise e

        # Add the response into the data section
        for item in new_exceptions:
            action_result.add_data(item.model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_vault_sandbox_analysis(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required Params
        vault_id = param["vault_id"]
        file_name = param["file_name"]
        vault_id = param["vault_id"]
        file_name = param["file_name"]
        # Optional Params
        doc_pass = param.get("document_pass", "")
        arc_pass = param.get("archive_pass", "")
        arguments = param.get("arguments", "None")

        # Initialize Pytmv1
        client = self._get_client()

        # Get file contents
        vault_info = vault.vault_info(vault_id=vault_id, file_name=file_name)
        file_found: bool = vault_info[0]
        if file_found is False:
            raise RuntimeError(f"VAULT RESPONSE: {vault_info[1]}. Please check arguments.")
        file_contents = b""
        file_path = ""
        try:
            file_path = vault_info[2][0]["path"]
        except FileNotFoundError:
            return f"Error: No valid file path returned. '{file_path}' does not exist."
        try:
            with open(file_path, "rb") as f:
                file_contents = f.read()
        except OSError:
            return f"Error: Could not read the file '{file_path}'."

        # Make rest call
        response = client.sandbox.submit_file(
            file=file_contents,
            file_name=file_name,
            document_password=doc_pass,
            archive_password=arc_pass,
            arguments=arguments,
        )
        # Check if an error occurred
        if self._is_pytmv1_error(response.result_code):
            self.debug_print(f"Something went wrong, please check vault_id: {vault_id} and file_name: {file_name}.")
            raise RuntimeError(f"Error submitting file to sandbox for analysis. Result Code: {response.error}")

        # Add the response into the data section
        action_result.add_data(self.unwrap(response.response).model_dump())

        # Return success
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())
        action_handler: Optional[Callable] = self.supported_actions.get(action_id)

        if action_handler is None:
            raise ValueError(f"Action requested ({action_id}) was not found")

        action_handler(param)

        return phantom.APP_SUCCESS

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        self.config = self.get_config()
        """
        # Access values in asset config by the name

        # Required Params
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """
        self.api_key = self.config["api_key"]
        self._base_url = self.config["api_url"]

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
    argparser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="verify",
        required=False,
        default=False,
    )

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = TrendMicroVisionOneConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=30)  # nosemgrep
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=30)  # nosemgrep
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
