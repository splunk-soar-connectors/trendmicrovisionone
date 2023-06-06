[comment]: # "Auto-generated SOAR connector documentation"
# Trend Micro Vision One for Splunk SOAR

Publisher: Trend Micro  
Connector Version: 1.1.0  
Product Vendor: Trend Micro  
Product Name: VisionOne  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) Trend Micro, 2022-2023"
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
# Splunk> Phantom

Welcome to the open-source repository for Splunk> Phantom's trendmicrovisionone App.

Please have a look at our [Contributing
Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) if you are
interested in contributing, raising issues, or learning more about open-source Phantom apps.

## Legal and License

This Phantom App is licensed under the Apache 2.0 license. Please see our [Contributing
Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice)
for further details.

#### Integration Author: Trend Micro

Support and maintenance for this integration are provided by the author. Please use the following
contact details:

-   **Email** : <integrations@trendmicro.com>

----------------------------------------------------------------------------------------------------

Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new
benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad
extended detection and response (XDR) capabilities that collect and automatically correlate data
across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro
Vision One prevents the majority of attacks with automated protection.

## Port Information

The app uses HTTPS protocol for communicating with the VisionOne API server. Below are the default
ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
| ------------ | ------------------ | ---- |
| https        | tcp                | 443  |

### Configuration Variables

The below configuration variables are required for this Connector to operate. These variables are
specified when configuring a Trend Micro Vision One asset in SOAR.

| VARIABLE    | REQUIRED | TYPE     | DESCRIPTION                   |
| ----------- | -------- | -------- | ----------------------------- |
| **api_url** | required | string   | The URL for your ETP instance |
| **api_key** | required | password | API key                       |

## Configure Trend Micro Vision One on Splunk SOAR

1.  Navigate to **Apps** \> **Unconfigured Apps** .
2.  Search for Trend Micro Vision One.
3.  Click **CONFIGURE NEW ASSET** to create and configure a new integration instance.
4.  ALternatively click on **INSTALL APP** and drop a tarball of the app

| **Parameter**              | **Description**                                                      | **Required** |
| -------------------------- | -------------------------------------------------------------------- | ------------ |
| Asset name                 | Unique name for this Trend Micro Vision One instance runner asset    | True         |
| Asset description          | Short description of the asset's purpose                             | True         |
| Product vendor             | Trend Micro                                                          | True         |
| Product name               | Vision One                                                           | True         |
| Tags                       | Optional tags to use in Playbooks                                    | False        |
| API_URL                    | Vision One API URL                                                   | True         |
| API_TOKEN                  | Vision One API Token                                                 | True         |
| Polling interval (minutes) | How often should security incident events be updated from Vision One | False        |

1.  Click **TEST CONNECTIVITY** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Splunk SOAR CLI, as part of an automation, or in a playbook.

#### Base Command

1.  `      Add To Block List     `

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and description | Required     |

#### Context Output

| **Path**                           | **Type**         | **Description**                                                     |
| ---------------------------------- | ---------------- | ------------------------------------------------------------------- |
| VisionOne.BlockList.multi_response | []multi_response | A list containing the http status code and task_id for action taken |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter.

1.  `      Remove From Block List     `

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_object      | Object object made up of type, value and description | Required     |

#### Context Output

| **Path**                           | **Type**         | **Description**                                                     |
| ---------------------------------- | ---------------- | ------------------------------------------------------------------- |
| VisionOne.BlockList.multi_response | []multi_response | A list containing the http status code and task_id for action taken |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter.

1.  `      Quarantine Email Message     `

#### Input

| **Argument Name** | **Description**                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------- | ------------ |
| email_identifiers | Email Identifiers consisting of message id, mailbox and description | Required     |

#### Context Output

| **Path**                       | **Type**         | **Description**                         |
| ------------------------------ | ---------------- | --------------------------------------- |
| VisionOne.Email.multi_response | []multi_response | Quarantine Email Message Response Array |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter.

1.  `      Delete Email Message     `

#### Input

| **Argument Name** | **Description**                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------- | ------------ |
| email_identifiers | Email Identifiers consisting of message id, mailbox and description | Required     |

#### Context Output

| **Path**                       | **Type**         | **Description**                     |
| ------------------------------ | ---------------- | ----------------------------------- |
| VisionOne.Email.multi_response | []multi_response | Delete Email Message Response Array |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter.

1.  `      Quarantine Device     `

#### Input

| **Argument Name**    | **Description**                                                                    | **Required** |
| -------------------- | ---------------------------------------------------------------------------------- | ------------ |
| endpoint_identifiers | Endpoint Identifiers consisting of endpoint(hostname or agentGuid) and description | Required     |

#### Context Output

| **Path**                                     | **Type**         | **Description**                    |
| -------------------------------------------- | ---------------- | ---------------------------------- |
| VisionOne.Endpoint_Connection.multi_response | []multi_response | Quarantine Endpoint Response Array |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`     20 minutes    ` .

1.  `      Unquarantine Device     `

#### Input

| **Argument Name**    | **Description**                                                                    | **Required** |
| -------------------- | ---------------------------------------------------------------------------------- | ------------ |
| endpoint_identifiers | Endpoint Identifiers consisting of endpoint(hostname or agentGuid) and description | Required     |

#### Context Output

| **Path**                                     | **Type**         | **Description**                 |
| -------------------------------------------- | ---------------- | ------------------------------- |
| VisionOne.Endpoint_Connection.multi_response | []multi_response | Restore Endpoint Response Array |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`     20 minutes    ` .

1.  `      Add To Exception List     `

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and description | Required     |

#### Context Output

| **Path**                                | **Type**         | **Description**                      |
| --------------------------------------- | ---------------- | ------------------------------------ |
| VisionOne.Exception_List.multi_response | []multi_response | Add To Exception List Response Array |

1.  `      delete from exception list     `

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and description | Required     |

#### Context Output

| **Path**                                | **Type**         | **Description**                           |
| --------------------------------------- | ---------------- | ----------------------------------------- |
| VisionOne.Exception_List.multi_response | []multi_response | Remove From Exception List Response Array |

1.  `      Add To Suspicious List     `

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and description | Required     |

#### Context Output

| **Path**                                 | **Type**         | **Description**                       |
| ---------------------------------------- | ---------------- | ------------------------------------- |
| VisionOne.Suspicious_List.multi_response | []multi_response | Add To Suspicious List Response Array |

1.  `      Delete From Suspicious List     `

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and description | Required     |

#### Context Output

| **Path**                                 | **Type**         | **Description**                            |
| ---------------------------------------- | ---------------- | ------------------------------------------ |
| VisionOne.Suspicious_List.multi_response | []multi_response | Delete from Suspicious List Response Array |

1.  `      terminate process     `

| **Argument Name**   | **Description**                                                                                                           | **Required** |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------ |
| process_identifiers | Process Identifiers consisting of endpoint(hostname or agentGuid), filesha1, filename(optional) and description(optional) | Required     |

#### Context Output

| **Path**                                   | **Type**         | **Description**                  |
| ------------------------------------------ | ---------------- | -------------------------------- |
| VisionOne.Terminate_Process.multi_response | []multi_response | Terminate Process Response Array |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout is
`     20 minutes    ` .

1.  `      Get Sandbox Submission Status     `

| **Argument Name** | **Description**                                                             | **Required** |
| ----------------- | --------------------------------------------------------------------------- | ------------ |
| task_id           | Task_id from the trendmicro-visionone-submit-file-to-sandbox command output | Required     |

#### Context Output

| **Path**                                             | **Type** | **Description**         |
| ---------------------------------------------------- | -------- | ----------------------- |
| VisionOne.File_Analysis_Status.id                    | String   | Message status          |
| VisionOne.File_Analysis_Status.status                | String   | Code status of the task |
| VisionOne.File_Analysis_Status.action                | String   | Task id                 |
| VisionOne.File_Analysis_Status.error                 | Object   | Task status             |
| VisionOne.File_Analysis_Status.digest                | Object   | Hash value of task      |
| VisionOne.File_Analysis_Status.created_date_time     | String   | Task completion time    |
| VisionOne.File_Analysis_Status.last_action_date_time | String   | Risk level of task      |
| VisionOne.File_Analysis_Status.resource_location     | String   | Description of task     |
| VisionOne.File_Analysis_Status.is_cached             | Boolean  | List of task detected   |
| VisionOne.File_Analysis_Status.arguments             | String   | Threat type list        |

1.  `      get file analysis report     `

| **Argument Name** | **Description**                                                                                              | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------ | ------------ |
| report_id         | report_id of the sandbox submission retrieved from the trendmicro-visionone-get-file-analysis-status command | Required     |
| type              | Type of report to retrieve: "vaReport", "investigationPackage", or "suspiciousObject"                        | Required     |

#### Context Output

| **Path**                                                | **Type** | **Description**               |
| ------------------------------------------------------- | -------- | ----------------------------- |
| VisionOne.File_Analysis_Report.message                  | String   | Message status                |
| VisionOne.File_Analysis_Report.code                     | String   | Code status of task           |
| VisionOne.File_Analysis_Report.type                     | String   | type of report                |
| VisionOne.File_Analysis_Report.value                    | String   | value of the above type       |
| VisionOne.File_Analysis_Report.risk_level               | String   | risk level of the file        |
| VisionOne.File_Analysis_Report.analysis_completion_time | String   | Final analysed time of report |
| VisionOne.File_Analysis_Report.expired_time             | String   | Expiry time of report         |
| VisionOne.File_Analysis_Report.root_file_sha1           | String   | sha value of the root file    |

1.  `      collect file     `

| **Argument Name** | **Description**                                                    | **Required** |
| ----------------- | ------------------------------------------------------------------ | ------------ |
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to collect file from | Required     |
| product_id        | Product: "sao" "xes" "sds"                                         | Required     |
| file_path         | Path of the forensic file to collect                               | Required     |
| os                | "windows", "mac" or "linux"                                        | Required     |
| description       | Description of file collected                                      | Optional     |

#### Context Output

| **Path**                                   | **Type** | **Description**               |
| ------------------------------------------ | -------- | ----------------------------- |
| VisionOne.Collect_Forensic_File.actionId   | String   | Action id of the running task |
| VisionOne.Collect_Forensic_File.taskStatus | String   | Status of the running task    |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`     20 minutes    ` .

1.  `      download information collected file     `

| **Argument Name** | **Description**                                                   | **Required** |
| ----------------- | ----------------------------------------------------------------- | ------------ |
| actionId          | actionId output from the collect command used to collect the file | Required     |

#### Context Output

| **Path**                                                            | **Type** | **Description**                                  |
| ------------------------------------------------------------------- | -------- | ------------------------------------------------ |
| VisionOne.Download_Information_For_Collected_Forensic_File.url      | String   | URL of the collected file                        |
| VisionOne.Download_Information_For_Collected_Forensic_File.expires  | String   | URL expiration date                              |
| VisionOne.Download_Information_For_Collected_Forensic_File.password | String   | Archive password for the protected forensic file |
| VisionOne.Download_Information_For_Collected_Forensic_File.filename | String   | Name of the collected file                       |

Note: The URL received from the
'trendmicro-visionone-download-information-for-collected-forensic-file' will be valid for only
`     60 seconds    `

1.  `      submit file to sandbox     `

| **Argument Name** | **Description**                                                                                                                                   | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| file_url          | URL pointing to the location of the file to be submitted.                                                                                         | Required     |
| filename          | Name of the file to be analyzed.                                                                                                                  | Required     |
| document_password | The password for decrypting the submitted document. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding. | Optional     |
| archive_password  | The password for decrypting the submitted archive. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding.  | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**                    |
| ---------------------------------------- | -------- | ---------------------------------- |
| VisionOne.Submit_File_to_Sandbox.message | String   | Message status of the sandbox file |
| VisionOne.Submit_File_to_Sandbox.code    | String   | Code status of the sandbox file    |
| VisionOne.Submit_File_to_Sandbox.task_id | String   | Task ID of the running task        |
| VisionOne.Submit_File_to_Sandbox.digest  | Object   | Sha value of the file              |

1.  `      status check     `

| **Argument Name** | **Description**                                            | **Required** |
| ----------------- | ---------------------------------------------------------- | ------------ |
| actionId          | Action ID of the task you would like to get the status of. | Required     |

#### Context Output

| **Path**                                 | **Type** | **Description**         |
| ---------------------------------------- | -------- | ----------------------- |
| VisionOne.Endpoint_Connection.actionId   | String   | The action id           |
| VisionOne.Endpoint_Connection.taskStatus | String   | Status of existing task |

1.  `      get endpoint info     `

| **Argument Name** | **Description**                                        | **Required** |
| ----------------- | ------------------------------------------------------ | ------------ |
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to query | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**                                                  |
| ------------------------------------- | -------- | ---------------------------------------------------------------- |
| VisionOne.Endpoint_Info.message       | String   | Message information from the request.                            |
| VisionOne.Endpoint_Info.errorCode     | Integer  | Error code.                                                      |
| VisionOne.Endpoint_Info.status        | String   | Status of the request.                                           |
| VisionOne.Endpoint_Info.logonAccount  | String   | Account currently logged on to the endpoint.                     |
| VisionOne.Endpoint_Info.hostname      | String   | Hostname.                                                        |
| VisionOne.Endpoint_Info.macAddr       | String   | MAC address.                                                     |
| VisionOne.Endpoint_Info.ip            | String   | IP address.                                                      |
| VisionOne.Endpoint_Info.osName        | String   | Operating System name.                                           |
| VisionOne.Endpoint_Info.osVersion     | String   | Operating System version.                                        |
| VisionOne.Endpoint_Info.osDescription | String   | Description of the Operating System.                             |
| VisionOne.Endpoint_Info.productCode   | String   | Product code of the Trend Micro product running on the endpoint. |

1.  `      add note     `

| **Argument Name**                     | **Description**                                 | **Required** |
| ------------------------------------- | ----------------------------------------------- | ------------ |
| source data identifier (workbench id) | Workbench id of security incident in Vision One | Required     |
| content                               | note to be added to the workbench event         | Required     |

#### Context Output

| **Path**                         | **Type** | **Description**                               |
| -------------------------------- | -------- | --------------------------------------------- |
| VisionOne.Add_Note.Workbench_Id  | String   | Workbench ID that the action was executed on. |
| VisionOne.Add_Note.noteId        | String   | Note ID.                                      |
| VisionOne.Add_Note.response_code | String   | Response code for the request.                |
| VisionOne.Add_Note.response_msg  | String   | Response message for the request.             |

1.  `      update status     `

| **Argument Name**                     | **Description**                                                                                                | **Required** |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------ |
| source data identifier (workbench_id) | The ID of the workbench alert that you would like to update the status for.                                    | Required     |
| status                                | The status to assign to the workbench alert: new, in_progress, resolved_false_positive, resolved_true_positive | Required     |

1.  `      get alert details     `

| **Argument Name**                     | **Description**                                                  | **Required** |
| ------------------------------------- | ---------------------------------------------------------------- | ------------ |
| source data identifier (workbench_id) | ID of the workbench alert you would like to get the details for. | Required     |

#### Context Output

| **Path**                          | **Type** | **Description**                                                     |
| --------------------------------- | -------- | ------------------------------------------------------------------- |
| VisionOne.Get_Alert_Details.alert | String   | Information associated to the workbenchID provided.                 |
| VisionOne.Get_Alert_Details.etag  | String   | An identifier for a specific version of a Workbench alert resource. |

1.  `      urls to sandbox     `

| **Argument Name** | **Description**                                                                                 | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------- | ------------ |
| urls              | Submits URLs to the sandbox for analysis. Note: You can submit a maximum of 10 URLs per request | Required     |

#### Context Output

| **Path**                          | **Type** | **Description**                                           |
| --------------------------------- | -------- | --------------------------------------------------------- |
| VisionOne.URLs_To_Sandbox.status  | String   | HTTP status code for the call.                            |
| VisionOne.URLs_To_Sandbox.task_id | String   | Unique alphanumeric string that identifies a submission.. |

1.  `      enable account     `

| **Argument Name**   | **Description**                                                             | **Required** |
| ------------------- | --------------------------------------------------------------------------- | ------------ |
| account_identifiers | Object containing `account_name` and optional `description` of action taken | Required     |

#### Context Output

| **Path**                         | **Type** | **Description**                                           |
| -------------------------------- | -------- | --------------------------------------------------------- |
| VisionOne.Enable_Account.status  | String   | HTTP status code for the call.                            |
| VisionOne.Enable_Account.task_id | String   | Unique alphanumeric string that identifies a submission.. |

1.  `      disable account     `

| **Argument Name**   | **Description**                                                             | **Required** |
| ------------------- | --------------------------------------------------------------------------- | ------------ |
| account_identifiers | Object containing `account_name` and optional `description` of action taken | Required     |

#### Context Output

| **Path**                          | **Type** | **Description**                                           |
| --------------------------------- | -------- | --------------------------------------------------------- |
| VisionOne.Disable_Account.status  | String   | HTTP status code for the call.                            |
| VisionOne.Disable_Account.task_id | String   | Unique alphanumeric string that identifies a submission.. |

1.  `      restore email message     `

| **Argument Name** | **Description**                                                                                | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------- | ------------ |
| email_identifiers | Object containing `mailbox` (Optional) and `message_id` or `unique_id` of the email to restore | Required     |

#### Context Output

| **Path**                                | **Type** | **Description**                                          |
| --------------------------------------- | -------- | -------------------------------------------------------- |
| VisionOne.Restore_Email_Message.status  | String   | HTTP status code for the call.                           |
| VisionOne.Restore_Email_Message.task_id | String   | Unique alphanumeric string that identifies a submission. |

1.  `      sign out account     `

| **Argument Name**   | **Description**                                                                          | **Required** |
| ------------------- | ---------------------------------------------------------------------------------------- | ------------ |
| account_identifiers | Object containing `account_name` and `description` (Optional) of the account to sign-out | Required     |

#### Context Output

| **Path**                           | **Type** | **Description**                                           |
| ---------------------------------- | -------- | --------------------------------------------------------- |
| VisionOne.Sign_Out_Account.status  | String   | HTTP status code for the call.                            |
| VisionOne.Sign_Out_Account.task_id | String   | Unique alphanumeric string that identifies a submission.. |

1.  `      force password reset     `

| **Argument Name**   | **Description**                                                                          | **Required** |
| ------------------- | ---------------------------------------------------------------------------------------- | ------------ |
| account_identifiers | Object containing `account_name` and `description` (Optional) of the account to sign-out | Required     |

#### Context Output

| **Path**                           | **Type** | **Description**                                           |
| ---------------------------------- | -------- | --------------------------------------------------------- |
| VisionOne.Sign_Out_Account.status  | String   | HTTP status code for the call.                            |
| VisionOne.Sign_Out_Account.task_id | String   | Unique alphanumeric string that identifies a submission.. |

1.  `      sandbox suspicious list     `

| **Argument Name** | **Description**                                          | **Required** |
| ----------------- | -------------------------------------------------------- | ------------ |
| submit_id         | Unique alphanumeric string that identifies a submission. | Required     |
| poll              | Should the result be polled?                             | Optional     |
| poll_time_sec     | How long should the result be polled for?                | Optional     |

#### Context Output

| **Path**                                                       | **Type** | **Description**                             |
| -------------------------------------------------------------- | -------- | ------------------------------------------- |
| VisionOne.Sandbox_Suspicious_List.sandbox_suspicious_list_resp | List     | List of object containing suspicious object |

1.  `      sandbox analysis result     `

| **Argument Name** | **Description**                                          | **Required** |
| ----------------- | -------------------------------------------------------- | ------------ |
| report_id         | Unique alphanumeric string that identifies a submission. | Required     |
| poll              | Should the result be polled?                             | Optional     |
| poll_time_sec     | How long should the result be polled for?                | Optional     |

#### Context Output

| **Path**                                                        | **Type** | **Description**                                                                       |
| --------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------- |
| VisionOne.Sandbox_Analysis_Result.id                            | String   | Unique alphanumeric string that identifies the analysis results of a submitted object |
| VisionOne.Sandbox_Analysis_Result.type                          | String   | Object type                                                                           |
| VisionOne.Sandbox_Analysis_Result.digest                        | String   | The hash values of the analyzed file                                                  |
| VisionOne.Sandbox_Analysis_Result.risk_level                    | String   | The risk level assigned to the object by the sandbox                                  |
| VisionOne.Sandbox_Analysis_Result.analysis_completion_date_time | String   | Timestamp in ISO 8601 format that indicates when the analysis was completed           |
| VisionOne.Sandbox_Analysis_Result.arguments                     | String   | Command line arguments encoded in Base64 of the submitted file                        |
| VisionOne.Sandbox_Analysis_Result.detection_names               | String   | The name of the threat as detected by the sandbox                                     |
| VisionOne.Sandbox_Analysis_Result.threat_types                  | String   | The threat type as detected by the sandbox                                            |
| VisionOne.Sandbox_Analysis_Result.true_file_type                | String   | File Type of the Object                                                               |

1.  `      sandbox investigation package     `

| **Argument Name** | **Description**                                          | **Required** |
| ----------------- | -------------------------------------------------------- | ------------ |
| submit_id         | Unique alphanumeric string that identifies a submission. | Required     |
| poll              | Should the result be polled?                             | Optional     |
| poll_time_sec     | How long should the result be polled for?                | Optional     |

#### Context Output

| **Path**                                   | **Type** | **Description**           |
| ------------------------------------------ | -------- | ------------------------- |
| VisionOne.Sandbox_Investigation_Package.id | File     | The output is a .zip file |

1.  `      Get Suspicious List     `

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| N/A               |                 |              |

#### Context Output

| **Path**                                         | **Type**             | **Description**                 |
| ------------------------------------------------ | -------------------- | ------------------------------- |
| VisionOne.Get_Suspicious_list.suspicious_objects | []suspicious_objects | Array of any Suspicious Objects |

1.  `      Get Exception List     `

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| N/A               |                 |              |

#### Context Output

| **Path**                                       | **Type**            | **Description**                |
| ---------------------------------------------- | ------------------- | ------------------------------ |
| VisionOne.Get_Exception_list.exception_objects | []exception_objects | Array of any Exception Objects |

This version of the Trend Micro app is compatible with Splunk SOAR version **5.1.0** and above.

## Authentication Information

The app uses HTTPS protocol for communicating with the Trend Micro Vision One server. For
authentication a Vision One API Token is used by the Splunk SOAR Connector.

----------------------------------------------------------------------------------------------------

[View Integration
Documentation](insert%20here%20link%20to%20documentation%20that%20will%20be%20published%20on%20Splunk%20docs)


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a VisionOne asset in SOAR.

| VARIABLE    | REQUIRED | TYPE     | DESCRIPTION                                              |
| ----------- | -------- | -------- | -------------------------------------------------------- |
| **api_url** | required | string   | Vision One API URL (e.g. https://api.xdr.trendmicro.com) |
| **api_key** | required | password | Vision One API Token                                     |

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get endpoint info](#action-get-endpoint-info) - Gather information about an endpoint  
[quarantine device](#action-quarantine-device) - Quarantine the endpoint  
[unquarantine device](#action-unquarantine-device) - Unquarantine the endpoint  
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality  
[status check](#action-status-check) - Checks the status of a task  
[add to blocklist](#action-add-to-blocklist) - Adds an item to the Suspicious Objects list in Vision One  
[remove from blocklist](#action-remove-from-blocklist) - Removes an item from the Suspicious Objects list  
[quarantine email message](#action-quarantine-email-message) - Quarantine the email message  
[delete email message](#action-delete-email-message) - Delete the email message  
[terminate process](#action-terminate-process) - Terminate the process running on the endpoint  
[add to exception](#action-add-to-exception) - Add object to exception list  
[delete from exception](#action-delete-from-exception) - Delete object from exception list  
[add to suspicious](#action-add-to-suspicious) - Add suspicious object to suspicious list  
[delete from suspicious](#action-delete-from-suspicious) - Delete the suspicious object from suspicious list  
[check analysis status](#action-check-analysis-status) - Get the status of file analysis based on task id  
[download analysis report](#action-download-analysis-report) - Get the analysis report of a file based on report id  
[collect forensic file](#action-collect-forensic-file) - Collect forensic file  
[forensic file info](#action-forensic-file-info) - Get the download information for collected forensic file  
[start analysis](#action-start-analysis) - Submit file to sandbox for analysis  
[add note](#action-add-note) - Adds a note to an existing workbench alert  
[update status](#action-update-status) - Updates the status of an existing workbench alert
[get alert details](#action-get-alert-details) - Displays information about the specified alert
[urls to sandbox](#action-urls-to-sandbox) - Submits URLs to the sandbox for analysis
[enable account](#action-enable-account) - Allows the user to sign in to new application and browser sessions
[disable account](#action-disable-account) - Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session
[restore email message](#action-restore-email-message) - Restore quarantined email messages
[sign out account](#action-sign-out-account) - Signs the user out of all active application and browser sessions
[force password reset](#action-force-password-reset) - Signs the user out of all active application and browser sessions, and forces the user to create a new password during the next sign-in attempt
[sandbox suspicious list](#action-sandbox-suspicious-list) - Downloads the suspicious object list associated to the specified object
[sandbox analysis result](#action-sandbox-analysis-result) - Displays the analysis results of the specified object
[sandbox investigation package](#action-sandbox-investigation-package) - Downloads the Investigation Package of the specified object
[get suspicious list](#action-get-suspicious-list) - Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs in the Suspicious Object List and displays the information in a paginated list
[get exception list](#action-get-exception-list) - Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs in the Exception List and displays it in a paginated list

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

Validate the asset configuration for connectivity using supplied configuration.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get endpoint info'
Gather information about an endpoint

Type: **generic**  
Read only: **False**

Gather information about an endpoint.

#### Action Parameters
| PARAMETER           | REQUIRED | DESCRIPTION                                         | TYPE   | CONTAINS                         |
| ------------------- | -------- | --------------------------------------------------- | ------ | -------------------------------- |
| **ip_hostname_mac** | required | Hostname/IP/MAC of the endpoint to query (Required) | string | `ip`  `mac address`  `host name` |

#### Action Output
| DATA PATH                                       | TYPE    | CONTAINS                         | EXAMPLE VALUES  |
| ----------------------------------------------- | ------- | -------------------------------- | --------------- |
| action_result.data.\*.status                    | string  |                                  |
| action_result.data.\*.errorCode                 | string  |                                  |
| action_result.data.\*.result.logonAccount.value | string  |                                  |
| action_result.data.\*.result.hostname.value     | string  |                                  |
| action_result.data.\*.result.macAddr.value      | string  | `mac address`                    |
| action_result.data.\*.result.ip.value           | string  | `ip`                             |
| action_result.data.\*.result.osName             | string  |                                  |
| action_result.data.\*.result.osVersion          | string  |                                  |
| action_result.data.\*.result.osDescription      | string  |                                  |
| action_result.data.\*.result.productCode        | string  |                                  |
| action_result.parameter.ip_hostname_mac         | string  | `ip`  `mac address`  `host name` |
| action_result.status                            | string  |                                  | success  failed |
| action_result.summary                           | string  |                                  |
| action_result.message                           | string  |                                  |
| summary.total_objects                           | numeric |                                  |
| summary.total_objects_successful                | numeric |                                  |

## action: 'quarantine device'
Quarantine the endpoint

Type: **contain**  
Read only: **False**

Quarantine the endpoint.

#### Action Parameters
| PARAMETER           | REQUIRED | DESCRIPTION                                                                           | TYPE   | CONTAINS                         |
| ------------------- | -------- | ------------------------------------------------------------------------------------- | ------ | -------------------------------- |
| **ip_hostname_mac** | required | Hostname/IP/MAC of endpoint to quarantine/isolate (Required)                          | string | `ip`  `mac address`  `host name` |
| **productid**       | required | Trend Micro product ID for quarantine task. 'sao' or 'sds'. Default: 'sao' (Required) | string |
| **description**     | optional | Description for this activity (Optional)                                              | string |

#### Action Output
| DATA PATH                               | TYPE    | CONTAINS                         | EXAMPLE VALUES  |
| --------------------------------------- | ------- | -------------------------------- | --------------- |
| action_result.data.\*.actionId          | string  | `action id`                      |
| action_result.data.\*.taskStatus        | string  |                                  |
| action_result.status                    | string  |                                  | success  failed |
| action_result.parameter.ip_hostname_mac | string  | `ip`  `mac address`  `host name` |
| action_result.parameter.productid       | string  |                                  |
| action_result.parameter.description     | string  |                                  |
| action_result.summary                   | string  |                                  |
| action_result.message                   | string  |                                  |
| summary.total_objects                   | numeric |                                  |
| summary.total_objects_successful        | numeric |                                  |

## action: 'unquarantine device'
Unquarantine the endpoint

Type: **correct**  
Read only: **False**

Unquarantine the endpoint.

#### Action Parameters
| PARAMETER           | REQUIRED | DESCRIPTION                                                                             | TYPE   | CONTAINS                         |
| ------------------- | -------- | --------------------------------------------------------------------------------------- | ------ | -------------------------------- |
| **ip_hostname_mac** | required | Hostname/IP/MAC of endpoint to unquarantine/restore connectivity for (Required)         | string | `ip`  `mac address`  `host name` |
| **productid**       | required | Trend Micro product ID for unquarantine task. 'sao' or 'sds'. Default: 'sao' (Required) | string |
| **description**     | optional | Description for this activity (Optional)                                                | string |

#### Action Output
| DATA PATH                               | TYPE    | CONTAINS                         | EXAMPLE VALUES  |
| --------------------------------------- | ------- | -------------------------------- | --------------- |
| action_result.data.\*.actionId          | string  | `action id`                      |
| action_result.data.\*.taskStatus        | string  |                                  |
| action_result.status                    | string  |                                  | success  failed |
| action_result.parameter.ip_hostname_mac | string  | `ip`  `mac address`  `host name` |
| action_result.parameter.productid       | string  |                                  |
| action_result.parameter.description     | string  |                                  |
| action_result.summary                   | string  |                                  |
| action_result.message                   | string  |                                  |
| summary.total_objects                   | numeric |                                  |
| summary.total_objects_successful        | numeric |                                  |

## action: 'on poll'
Callback action for the on_poll ingest functionality

Type: **ingest**  
Read only: **True**

Callback action for the on_poll ingest functionality.

#### Action Parameters
| PARAMETER     | REQUIRED | DESCRIPTION                                                                | TYPE    | CONTAINS |
| ------------- | -------- | -------------------------------------------------------------------------- | ------- | -------- |
| **starttime** | optional | Make sure time format matches following example (2020-06-15T10:00:00.000Z) | string  |
| **endtime**   | optional | Make sure time format matches following example (2020-06-15T12:00:00.000Z) | string  |
| **limit**     | optional | Limit of polling results. Default: limit=100                               | numeric |

#### Action Output
No Output  

## action: 'status check'
Checks the status of a task

Type: **investigate**  
Read only: **False**

Checks the status of a particular task.

#### Action Parameters
| PARAMETER     | REQUIRED | DESCRIPTION                                                          | TYPE   | CONTAINS    |
| ------------- | -------- | -------------------------------------------------------------------- | ------ | ----------- |
| **action_id** | required | Action ID of the task you would like to get the status of (Required) | string | `action id` |

#### Action Output
| DATA PATH                         | TYPE    | CONTAINS    | EXAMPLE VALUES  |
| --------------------------------- | ------- | ----------- | --------------- |
| action_result.parameter.action_id | string  | `action id` |
| action_result.data.\*.taskStatus  | string  |             |
| action_result.status              | string  |             | success  failed |
| action_result.summary             | string  |             |
| action_result.message             | string  |             |
| summary.total_objects             | numeric |             |
| summary.total_objects_successful  | numeric |             |

## action: 'add to blocklist'
Adds an item to the Suspicious Objects list in Vision One

Type: **contain**  
Read only: **False**

Adds an item from the Trend Micro Vision One Suspicious Objects list.

#### Action Parameters
| PARAMETER        | REQUIRED | DESCRIPTION                                                                               | TYPE   | CONTAINS |
| ---------------- | -------- | ----------------------------------------------------------------------------------------- | ------ | -------- |
| **value_type**   | required | Type of object to be added ('domain', 'ip', 'sha1', or 'url') (Required)                  | string |
| **target_value** | required | The object you would like to add to the block list that matches the value-type (Required) | string |
| **product_id**   | optional | Trend Micro ID of product (Optional)                                                      | string |
| **description**  | optional | Description for this activity (Optional)                                                  | string |

#### Action Output
| DATA PATH                            | TYPE    | CONTAINS    | EXAMPLE VALUES  |
| ------------------------------------ | ------- | ----------- | --------------- |
| action_result.data.\*.actionId       | string  | `action id` |
| action_result.data.\*.taskStatus     | string  |             |
| action_result.status                 | string  |             | success  failed |
| action_result.parameter.description  | string  |             |
| action_result.parameter.product_id   | string  |             |
| action_result.parameter.target_value | string  |             |
| action_result.parameter.value_type   | string  |             |
| action_result.summary                | string  |             |
| action_result.message                | string  |             |
| summary.total_objects                | numeric |             |
| summary.total_objects_successful     | numeric |             |

## action: 'remove from blocklist'
Removes an item from the Suspicious Objects list

Type: **correct**  
Read only: **False**

Removes an item from the Trend Micro Vision One Suspicious Objects list.

#### Action Parameters
| PARAMETER        | REQUIRED | DESCRIPTION                                                                                | TYPE   | CONTAINS |
| ---------------- | -------- | ------------------------------------------------------------------------------------------ | ------ | -------- |
| **value_type**   | required | Type of object to be removed ('domain', 'ip', 'sha1', or 'url') (Required)                 | string |
| **target_value** | required | The object you would like to remove from block list that matches the value-type (Required) | string |
| **product_id**   | optional | Trend Micro ID of product (Optional)                                                       | string |
| **description**  | optional | Description for this activity (Optional)                                                   | string |

#### Action Output
| DATA PATH                            | TYPE    | CONTAINS    | EXAMPLE VALUES  |
| ------------------------------------ | ------- | ----------- | --------------- |
| action_result.data.\*.actionId       | string  | `action id` |
| action_result.data.\*.taskStatus     | string  |             |
| action_result.status                 | string  |             | success  failed |
| action_result.parameter.description  | string  |             |
| action_result.parameter.product_id   | string  |             |
| action_result.parameter.target_value | string  |             |
| action_result.parameter.value_type   | string  |             |
| action_result.summary                | string  |             |
| action_result.message                | string  |             |
| summary.total_objects                | numeric |             |
| summary.total_objects_successful     | numeric |             |

## action: 'quarantine email message'
Quarantine the email message

Type: **contain**  
Read only: **False**

Retrieve data from the quarantine email message and send the result to dashboard.

#### Action Parameters
| PARAMETER                 | REQUIRED | DESCRIPTION                                                                         | TYPE   | CONTAINS |
| ------------------------- | -------- | ----------------------------------------------------------------------------------- | ------ | -------- |
| **message_id**            | required | Email Message ID from Trend Micro Vision One message activity data (Required)       | string |
| **mailbox**               | required | Email mailbox where the message will be quarantied from (Required)                  | string |
| **message_delivery_time** | optional | Email message's original delivery time (format=YYYY-MM-DDTHH:MM:SS.000Z) (Required) | string |
| **product_id**            | optional | Target product ID (Optional)                                                        | string |
| **description**           | optional | Description for this activity (Optional)                                            | string |

#### Action Output
| DATA PATH                                     | TYPE    | CONTAINS    | EXAMPLE VALUES  |
| --------------------------------------------- | ------- | ----------- | --------------- |
| action_result.data.\*.actionId                | string  | `action id` |
| action_result.data.\*.taskStatus              | string  |             |
| action_result.status                          | string  |             | success  failed |
| action_result.parameter.message_id            | string  |             |
| action_result.parameter.mailbox               | string  |             |
| action_result.parameter.message_delivery_time | string  |             |
| action_result.parameter.product_id            | string  |             |
| action_result.parameter.description           | string  |             |
| action_result.summary                         | string  |             |
| action_result.message                         | string  |             |
| summary.total_objects                         | numeric |             |
| summary.total_objects_successful              | numeric |             |

## action: 'delete email message'
Delete the email message

Type: **correct**  
Read only: **False**

Retrieve data from the delete email message and relay result to Splunk.

#### Action Parameters
| PARAMETER                 | REQUIRED | DESCRIPTION                                                                         | TYPE   | CONTAINS |
| ------------------------- | -------- | ----------------------------------------------------------------------------------- | ------ | -------- |
| **message_id**            | required | Email Message ID from Trend Micro Vision One message activity data (Required)       | string |
| **mailbox**               | required | Email mailbox where the message will be deleted from (Required)                     | string |
| **message_delivery_time** | optional | Email message's original delivery time (format=YYYY-MM-DDTHH:MM:SS.000Z) (Required) | string |
| **product_id**            | optional | Target product ID (Optional)                                                        | string |
| **description**           | optional | Description for this activity (Optional)                                            | string |

#### Action Output
| DATA PATH                                     | TYPE    | CONTAINS    | EXAMPLE VALUES  |
| --------------------------------------------- | ------- | ----------- | --------------- |
| action_result.data.\*.actionId                | string  | `action id` |
| action_result.data.\*.taskStatus              | string  |             |
| action_result.status                          | string  |             | success  failed |
| action_result.parameter.message_id            | string  |             |
| action_result.parameter.mailbox               | string  |             |
| action_result.parameter.message_delivery_time | string  |             |
| action_result.parameter.product_id            | string  |             |
| action_result.parameter.description           | string  |             |
| action_result.summary                         | string  |             |
| action_result.message                         | string  |             |
| summary.total_objects                         | numeric |             |
| summary.total_objects_successful              | numeric |             |

## action: 'terminate process'
Terminate the process running on the endpoint

Type: **contain**  
Read only: **False**

Terminate the process running on the endpoint and send results to the dashboard.

#### Action Parameters
| PARAMETER           | REQUIRED | DESCRIPTION                                                                | TYPE   | CONTAINS |
| ------------------- | -------- | -------------------------------------------------------------------------- | ------ | -------- |
| **ip_hostname_mac** | required | Hostname, macaddr or ip of the endpoint to terminate process on (Required) | string |
| **product_id**      | optional | Target product. Default: 'sao' (Optional)                                  | string |
| **description**     | optional | Description for this activity (Optional)                                   | string |
| **file_sha1**       | required | SHA1 hash of the process to terminate (Required)                           | string |
| **filename**        | optional | File name for log (Optional)                                               | string |

#### Action Output
| DATA PATH                               | TYPE    | CONTAINS    | EXAMPLE VALUES  |
| --------------------------------------- | ------- | ----------- | --------------- |
| action_result.data.\*.actionId          | string  | `action id` |
| action_result.data.\*.taskStatus        | string  |             |
| action_result.status                    | string  |             | success  failed |
| action_result.parameter.ip_hostname_mac | string  |             |
| action_result.parameter.product_id      | string  |             |
| action_result.parameter.description     | string  |             |
| action_result.parameter.file_sha1       | string  |             |
| action_result.parameter.filename        | string  |             |
| action_result.summary                   | string  |             |
| action_result.message                   | string  |             |
| summary.total_objects                   | numeric |             |
| summary.total_objects_successful        | numeric |             |

## action: 'add to exception'
Add object to exception list

Type: **correct**  
Read only: **False**

Add the exception object to the exception list and send the result to Splunk.

#### Action Parameters
| PARAMETER       | REQUIRED | DESCRIPTION                                                                                                                                                                                                                                                                                                                                                                                                                       | TYPE   | CONTAINS |
| --------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| **type**        | required | The object type: 'domain', 'ip', 'sha1', or 'url' (Required)                                                                                                                                                                                                                                                                                                                                                                      | string |
| **value**       | required | Full and partial matches supported. Domain partial match, (with a wildcard as the subdomain, example, .example.com) IP partial match, (IP range example, 192.168.35.1-192.168.35.254, cidr example, 192.168.35.1/24) URL partial match, (Supports wildcards 'http://.'', 'https://.'' at beginning, or ''' at the end. Multiple wild cards also supported, such as , https://.example.com/path1/) SHA1 only full match (Required) | string |
| **description** | optional | Description for this activity (Optional)                                                                                                                                                                                                                                                                                                                                                                                          | string |

#### Action Output
| DATA PATH                           | TYPE    | CONTAINS | EXAMPLE VALUES  |
| ----------------------------------- | ------- | -------- | --------------- |
| action_result.data.\*.message       | string  |          |
| action_result.data.\*.status_code   | string  |          |
| action_result.data.\*.total_items   | numeric |          |
| action_result.status                | string  |          | success  failed |
| action_result.parameter.description | string  |          |
| action_result.parameter.type        | string  |          |
| action_result.parameter.value       | string  |          |
| action_result.summary               | string  |          |
| action_result.message               | string  |          |
| summary.total_objects               | numeric |          |
| summary.total_objects_successful    | numeric |          |

## action: 'delete from exception'
Delete object from exception list

Type: **correct**  
Read only: **False**

Delete the exception object from the exception list and relay data to Splunk.

#### Action Parameters
| PARAMETER       | REQUIRED | DESCRIPTION                                                  | TYPE   | CONTAINS |
| --------------- | -------- | ------------------------------------------------------------ | ------ | -------- |
| **type**        | required | The object type: 'domain', 'ip', 'sha1', or 'url' (Required) | string |
| **value**       | required | The object value (Required)                                  | string |
| **description** | optional | Description for this activity (Optional)                     | string |

#### Action Output
| DATA PATH                           | TYPE    | CONTAINS | EXAMPLE VALUES  |
| ----------------------------------- | ------- | -------- | --------------- |
| action_result.data.\*.message       | string  |          |
| action_result.data.\*.status_code   | string  |          |
| action_result.data.\*.total_items   | numeric |          |
| action_result.status                | string  |          | success  failed |
| action_result.parameter.description | string  |          |
| action_result.parameter.type        | string  |          |
| action_result.parameter.value       | string  |          |
| action_result.summary               | string  |          |
| action_result.message               | string  |          |
| summary.total_objects               | numeric |          |
| summary.total_objects_successful    | numeric |          |

## action: 'add to suspicious'
Add suspicious object to suspicious list

Type: **contain**  
Read only: **False**

Add suspicious object to suspicious list and send the result to dashboard.

#### Action Parameters
| PARAMETER       | REQUIRED | DESCRIPTION                                                                                                                                                                            | TYPE    | CONTAINS |
| --------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | -------- |
| **type**        | required | The object type: 'domain', 'ip', 'sha1', or 'url' (Required)                                                                                                                           | string  |
| **value**       | required | The object value (Required)                                                                                                                                                            | string  |
| **description** | optional | Description for this activity (Optional)                                                                                                                                               | string  |
| **scan_action** | optional | The action to take if object is found. If you don't use this parameter, the scan action specified in default_settings.riskLevel.type will be used instead. 'block' or 'log' (Optional) | string  |
| **risk_level**  | optional | The Suspicious Object risk level. If you don't use this parameter, high will be used instead. risk level (either 'high', 'medium' or 'low') (Optional)                                 | string  |
| **expiry**      | optional | The number of days to keep the object in the Suspicious Object List. If you don't use this parameter, the default_settings.expiredDay scan action will be used instead (Optional)      | numeric |

#### Action Output
| DATA PATH                           | TYPE    | CONTAINS | EXAMPLE VALUES  |
| ----------------------------------- | ------- | -------- | --------------- |
| action_result.data.\*.message       | string  |          |
| action_result.data.\*.status_code   | string  |          |
| action_result.data.\*.total_items   | numeric |          |
| action_result.status                | string  |          | success  failed |
| action_result.parameter.description | string  |          |
| action_result.parameter.type        | string  |          |
| action_result.parameter.value       | string  |          |
| action_result.parameter.scan_action | string  |          |
| action_result.parameter.risk_level  | string  |          |
| action_result.parameter.expiry      | string  |          |
| action_result.summary               | string  |          |
| action_result.message               | string  |          |
| summary.total_objects               | numeric |          |
| summary.total_objects_successful    | numeric |          |

## action: 'delete from suspicious'
Delete the suspicious object from suspicious list

Type: **correct**  
Read only: **False**

Delete the suspicious object from suspicious list and send the result to the dashboard.

#### Action Parameters
| PARAMETER | REQUIRED | DESCRIPTION                                                  | TYPE   | CONTAINS |
| --------- | -------- | ------------------------------------------------------------ | ------ | -------- |
| **type**  | required | The object type: 'domain', 'ip', 'sha1', or 'url' (Required) | string |
| **value** | required | The object value (Required)                                  | string |

#### Action Output
| DATA PATH                         | TYPE    | CONTAINS | EXAMPLE VALUES  |
| --------------------------------- | ------- | -------- | --------------- |
| action_result.data.\*.message     | string  |          |
| action_result.data.\*.status_code | string  |          |
| action_result.data.\*.total_items | numeric |          |
| action_result.status              | string  |          | success  failed |
| action_result.parameter.type      | string  |          |
| action_result.parameter.value     | string  |          |
| action_result.summary             | string  |          |
| action_result.message             | string  |          |
| summary.total_objects             | numeric |          |
| summary.total_objects_successful  | numeric |          |

## action: 'check analysis status'
Get the status of file analysis based on task id

Type: **investigate**  
Read only: **False**

Get the status of file analysis based on task id and send result to the dashboard.

#### Action Parameters
| PARAMETER   | REQUIRED | DESCRIPTION                                                                                                 | TYPE   | CONTAINS  |
| ----------- | -------- | ----------------------------------------------------------------------------------------------------------- | ------ | --------- |
| **task_id** | required | Task_id from the trendmicro-visionone-start-analysis command output. Submission ID in Vision One (Required) | string | `task id` |

#### Action Output
| DATA PATH                                                         | TYPE    | CONTAINS    | EXAMPLE VALUES  |
| ----------------------------------------------------------------- | ------- | ----------- | --------------- |
| action_result.data.\*.message                                     | string  |             |
| action_result.data.\*.code                                        | string  |             |
| action_result.data.\*.data.taskId                                 | string  | `task id`   |
| action_result.data.\*.data.taskStatus                             | string  |             |
| action_result.data.\*.data.digest                                 | string  |             |
| action_result.data.\*.data.analysisSummary.analysisCompletionTime | string  |             |
| action_result.data.\*.data.analysisSummary.riskLevel              | string  |             |
| action_result.data.\*.data.analysisSummary.description            | string  |             |
| action_result.data.\*.data.analysisSummary.detectionNameList      | string  |             |
| action_result.data.\*.data.analysisSummary.threatTypeList         | string  |             |
| action_result.data.\*.data.analysisSummary.trueFileType           | string  |             |
| action_result.data.\*.data.reportId                               | numeric | `report id` |
| action_result.status                                              | string  |             | success  failed |
| action_result.parameter.task_id                                   | string  | `task id`   |
| action_result.summary                                             | string  |             |
| action_result.message                                             | string  |             |
| summary.total_objects                                             | numeric |             |
| summary.total_objects_successful                                  | numeric |             |

## action: 'download analysis report'
Get the analysis report of a file based on report id

Type: **investigate**  
Read only: **False**

Get the analysis report of a file based on report id and send the results to the dashboard.

#### Action Parameters
| PARAMETER     | REQUIRED | DESCRIPTION                                                                                                          | TYPE   | CONTAINS |
| ------------- | -------- | -------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| **report_id** | required | Report_id of the sandbox submission retrieved from the trendmicro-visionone-check-analysis-status command (Required) | string |
| **type**      | required | Type of report to retrieve: 'vaReport', 'nvestigationPackage', or 'suspiciousObject' (Required)                      | string |

#### Action Output
| DATA PATH                         | TYPE    | CONTAINS | EXAMPLE VALUES  |
| --------------------------------- | ------- | -------- | --------------- |
| action_result.parameter.report_id | string  |          |
| action_result.parameter.type      | string  |          |
| action_result.status              | string  |          | success  failed |
| action_result.data                | string  |          |
| action_result.summary             | string  |          |
| action_result.message             | string  |          |
| summary.total_objects             | numeric |          |
| summary.total_objects_successful  | numeric |          |

## action: 'collect forensic file'
Collect forensic file

Type: **investigate**  
Read only: **False**

Collect forensic file and send result to the dashboard.

#### Action Parameters
| PARAMETER           | REQUIRED | DESCRIPTION                                                             | TYPE   | CONTAINS |
| ------------------- | -------- | ----------------------------------------------------------------------- | ------ | -------- |
| **ip_hostname_mac** | required | IP/Hostname/MAC address of the endpoint to collect file from (Required) | string |
| **product_id**      | required | Product: 'sao' 'xes' 'sds' (Required)                                   | string |
| **description**     | optional | Description of file collected (Optional)                                | string |
| **file_path**       | required | Path of the forensic file to collect (Required)                         | string |
| **os**              | optional | OS type (mac, windows or linux without version numbers) (Required)      | string |

#### Action Output
| DATA PATH                               | TYPE    | CONTAINS    | EXAMPLE VALUES  |
| --------------------------------------- | ------- | ----------- | --------------- |
| action_result.data.\*.actionId          | string  | `action id` |
| action_result.data.\*.taskStatus        | string  |             |
| action_result.status                    | string  |             | success  failed |
| action_result.parameter.ip_hostname_mac | string  |             |
| action_result.parameter.product_id      | string  |             |
| action_result.parameter.description     | string  |             |
| action_result.parameter.file_path       | string  |             |
| action_result.parameter.os              | string  |             |
| action_result.summary                   | string  |             |
| action_result.message                   | string  |             |
| summary.total_objects                   | numeric |             |
| summary.total_objects_successful        | numeric |             |

## action: 'forensic file info'
Get the download information for collected forensic file

Type: **investigate**  
Read only: **False**

Get the download information for collected forensic file and send the result to the dashboard.

#### Action Parameters
| PARAMETER     | REQUIRED | DESCRIPTION                                                                  | TYPE   | CONTAINS    |
| ------------- | -------- | ---------------------------------------------------------------------------- | ------ | ----------- |
| **action_id** | required | ActionId output from the collect command used to collect the file (Required) | string | `action id` |

#### Action Output
| DATA PATH                           | TYPE    | CONTAINS                        | EXAMPLE VALUES  |
| ----------------------------------- | ------- | ------------------------------- | --------------- |
| action_result.data.\*.data.url      | string  | `file url`  `url`               |
| action_result.data.\*.data.expires  | string  |                                 |
| action_result.data.\*.data.password | string  | `document pass`  `archive pass` |
| action_result.data.\*.data.filename | string  | `file name`                     |
| action_result.parameter.action_id   | string  | `action id`                     |
| action_result.status                | string  |                                 | success  failed |
| action_result.summary               | string  |                                 |
| action_result.message               | string  |                                 |
| summary.total_objects               | numeric |                                 |
| summary.total_objects_successful    | numeric |                                 |

## action: 'start analysis'
Submit file to sandbox for analysis

Type: **investigate**  
Read only: **False**

Submit file to sandbox for analysis and send the result to the dashboard.

#### Action Parameters
| PARAMETER         | REQUIRED | DESCRIPTION                                                                                                                                                 | TYPE   | CONTAINS |
| ----------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| **file_url**      | required | URL pointing to the location of the file to be submitted (Required)                                                                                         | string |
| **file_name**     | required | Name of the file to be analyzed (Required)                                                                                                                  | string |
| **document_pass** | optional | The password for decrypting the submitted document. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding (Optional) | string |
| **archive_pass**  | optional | The password for decrypting the submitted archive. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding (Optional)  | string |

#### Action Output
| DATA PATH                             | TYPE    | CONTAINS  | EXAMPLE VALUES  |
| ------------------------------------- | ------- | --------- | --------------- |
| action_result.data.\*.code            | string  |           |
| action_result.data.\*.message         | string  |           |
| action_result.data.\*.data.taskId     | string  | `task id` |
| action_result.data.\*.data.digest     | string  |           |
| action_result.status                  | string  |           | success  failed |
| action_result.parameter.file_url      | string  |           |
| action_result.parameter.file_name     | string  |           |
| action_result.parameter.document_pass | string  |           |
| action_result.parameter.archive_pass  | string  |           |
| action_result.summary                 | string  |           |
| action_result.message                 | string  |           |
| summary.total_objects                 | numeric |           |
| summary.total_objects_successful      | numeric |           |

## action: 'add note'
Adds a note to an existing workbench alert

Type: **generic**  
Read only: **False**

Adds a note to an existing workbench alert in Trend Micro Vision One.

#### Action Parameters
| PARAMETER        | REQUIRED | DESCRIPTION                                                | TYPE   | CONTAINS                 |
| ---------------- | -------- | ---------------------------------------------------------- | ------ | ------------------------ |
| **workbench_id** | required | Workbench id of security incident in Vision One (Required) | string | `source data identifier` |
| **content**      | required | Note to be added to workbench event (Required)             | string |

#### Action Output
| DATA PATH                            | TYPE    | CONTAINS                 | EXAMPLE VALUES  |
| ------------------------------------ | ------- | ------------------------ | --------------- |
| action_result.data.\*.info.code      | string  |                          |
| action_result.data.\*.info.msg       | string  |                          |
| action_result.data.\*.data.id        | string  |                          |
| action_result.status                 | string  |                          | success  failed |
| action_result.parameter.workbench_id | string  | `source data identifier` |
| action_result.parameter.content      | string  |                          |
| action_result.summary                | string  |                          |
| action_result.message                | string  |                          |
| summary.total_objects                | numeric |                          |
| summary.total_objects_successful     | numeric |                          |

## action: 'update status'
Updates the status of an existing workbench alert

Type: **correct**  
Read only: **False**

Updates the status of an existing workbench alert in Trend Micro Vision One.

#### Action Parameters
| PARAMETER        | REQUIRED | DESCRIPTION                                                                                                               | TYPE   | CONTAINS                 |
| ---------------- | -------- | ------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------ |
| **workbench_id** | required | The ID of the workbench alert that you would like to update the status for (Required)                                     | string | `source data identifier` |
| **status**       | required | The status to assign to the workbench alert: new, in_progress, resolved_false_positive, resolved_true_positive (Required) | string |

#### Action Output
| DATA PATH                            | TYPE    | CONTAINS                 | EXAMPLE VALUES  |
| ------------------------------------ | ------- | ------------------------ | --------------- |
| action_result.data.\*.info.code      | string  |                          |
| action_result.data.\*.info.msg       | string  |                          |
| action_result.data.\*.data           | string  |                          |
| action_result.status                 | string  |                          | success  failed |
| action_result.parameter.workbench_id | string  | `source data identifier` |
| action_result.parameter.status       | string  |                          |
| action_result.summary                | string  |                          |
| action_result.message                | string  |                          |
| summary.total_objects                | numeric |                          |
| summary.total_objects_successful     | numeric |                          |

## action: 'get alert details'
Displays information about the specified alert

Type: **investigate**  
Read only: **False**

Displays information about the specified alert.

#### Action Parameters
| PARAMETER        | REQUIRED | DESCRIPTION                                                                     | TYPE   | CONTAINS |
| ---------------- | -------- | ------------------------------------------------------------------------------- | ------ | -------- |
| **workbench_id** | required | The ID of the workbench alert that you would like to get details for (Required) | string |          |

#### Action Output
| DATA PATH                            | TYPE    | CONTAINS | EXAMPLE VALUES                   |
| ------------------------------------ | ------- | -------- | -------------------------------- |
| action_result.parameter.workbench_id | string  |          | WB-14-20190709-00003             |
| action_result.etag                   | string  |          | d41d8cd98f00b204e9800998ecf8427e |
| action_result.alert                  | string  |          |
| action_result.message                | string  |          | success  failed                  |
| summary.total_objects                | numeric |          |
| summary.total_objects_successful     | numeric |          |

## action: 'urls to sandbox'
Submits URLs to the sandbox for analysis.

Type: **investigate**  
Read only: **False**

Submits URLs to the sandbox for analysis.

#### Action Parameters
| PARAMETER | REQUIRED | DESCRIPTION                                                                                 | TYPE   | CONTAINS |
| --------- | -------- | ------------------------------------------------------------------------------------------- | ------ | -------- |
| **urls**  | required | A list of URLs to be analyzed. A maximum of 10 URLs can be submitted per request (Required) | string |          |

#### Action Output
| DATA PATH                        | TYPE    | CONTAINS | EXAMPLE VALUES                 |
| -------------------------------- | ------- | -------- | ------------------------------ |
| action_result.parameter.urls     | string  |          | "<https://www.trendmicro.com>" |
| action_result.status             | string  |          |                                |
| action_result.message            | string  |          | success  failed                |
| summary.total_objects            | numeric |          |
| summary.total_objects_successful | numeric |          |

## action: 'enable account'
Allows the user to sign in to new application and browser sessions.

Type: **correct**  
Read only: **False**

Allows the user to sign in to new application and browser sessions.

#### Action Parameters
| PARAMETER               | REQUIRED | DESCRIPTION                                                                                                                               | TYPE   | CONTAINS |
| ----------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| **account_identifiers** | required | An object containing the `account_name` (Required) for the user account to be enabled and a `description` (Optional) for the action taken | string |

#### Action Output
| DATA PATH                                   | TYPE    | CONTAINS | EXAMPLE VALUES                                                       |
| ------------------------------------------- | ------- | -------- | -------------------------------------------------------------------- |
| action_result.parameter.account_identifiers | string  |          | [{"description":"enable account","account_name":"example@test.com"}] |
| action_result.status                        | string  |          | success  failed                                                      |
| action_result.message                       | string  |          |
| summary.total_objects                       | numeric |          |
| summary.total_objects_successful            | numeric |          |

## action: 'disable account'
Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session.

Type: **correct**  
Read only: **False**

Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session.

#### Action Parameters
| PARAMETER               | REQUIRED | DESCRIPTION                                                                                                                                | TYPE   | CONTAINS |
| ----------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------ | -------- |
| **account_identifiers** | required | An object containing the `account_name` (Required) for the user account to be disabled and a `description` (Optional) for the action taken | string |

#### Action Output
| DATA PATH                                   | TYPE    | CONTAINS | EXAMPLE VALUES                                                        |
| ------------------------------------------- | ------- | -------- | --------------------------------------------------------------------- |
| action_result.parameter.account_identifiers | string  |          | [{"description":"disable account","account_name":"example@test.com"}] |
| action_result.status                        | string  |          | success  failed                                                       |
| action_result.message                       | string  |          |
| summary.total_objects                       | numeric |          |
| summary.total_objects_successful            | numeric |          |

## action: 'restore email message'
Restore quarantined email messages.

Type: **correct**  
Read only: **False**

Restore quarantined email messages.

#### Action Parameters
| PARAMETER             | REQUIRED | DESCRIPTION                                                                                                                                    | TYPE   | CONTAINS |
| --------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| **email_identifiers** | required | An object containing the `mailbox` and `message_id` (Required) of the email to be restored and a `description` (Optional) for the action taken | string |

#### Action Output
| DATA PATH                                 | TYPE    | CONTAINS | EXAMPLE VALUES                                                                               |
| ----------------------------------------- | ------- | -------- | -------------------------------------------------------------------------------------------- |
| action_result.parameter.email_identifiers | string  |          | [{"mailbox":"example@test.com","message_id":"xsd123","description":"restore email message"}] |
| action_result.status                      | string  |          | success  failed                                                                              |
| action_result.message                     | string  |          |
| summary.total_objects                     | numeric |          |
| summary.total_objects_successful          | numeric |          |

## action: 'sign out account'
Signs the user out of all active application and browser sessions.

Type: **contain**  
Read only: **False**

Signs the user out of all active application and browser sessions.

#### Action Parameters
| PARAMETER               | REQUIRED | DESCRIPTION                                                                                                                                  | TYPE   | CONTAINS |
| ----------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| **account_identifiers** | required | An object containing the `account_name` (Required) for the user account to be signed out and a `description` (Optional) for the action taken | string |

#### Action Output
| DATA PATH                                   | TYPE    | CONTAINS | EXAMPLE VALUES                                                        |
| ------------------------------------------- | ------- | -------- | --------------------------------------------------------------------- |
| action_result.parameter.account_identifiers | string  |          | [{"description":"disable account","account_name":"example@test.com"}] |
| action_result.status                        | string  |          | success  failed                                                       |
| action_result.message                       | string  |          |
| summary.total_objects                       | numeric |          |
| summary.total_objects_successful            | numeric |          |

## action: 'force password reset'
Signs the user out of all active application and browser sessions, and forces the user to create a new password during the next sign-in attempt.

Type: **contain**  
Read only: **False**

Signs the user out of all active application and browser sessions, and forces the user to create a new password during the next sign-in attempt.

#### Action Parameters
| PARAMETER               | REQUIRED | DESCRIPTION                                                                                                                                  | TYPE   | CONTAINS |
| ----------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| **account_identifiers** | required | An object containing the `account_name` (Required) for the user account to be signed out and a `description` (Optional) for the action taken | string |

#### Action Output
| DATA PATH                                   | TYPE    | CONTAINS | EXAMPLE VALUES                                                       |
| ------------------------------------------- | ------- | -------- | -------------------------------------------------------------------- |
| action_result.parameter.account_identifiers | string  |          | [{"description":"reset password","account_name":"example@test.com"}] |
| action_result.status                        | string  |          | success  failed                                                      |
| action_result.message                       | string  |          |
| summary.total_objects                       | numeric |          |
| summary.total_objects_successful            | numeric |          |

## action: 'sandbox suspicious list'
Downloads the suspicious object list associated to the specified object.

Type: **investigate**  
Read only: **False**

Downloads the suspicious object list associated to the specified object. Note: Suspicious Object Lists are only available for objects with a high risk level.

#### Action Parameters
| PARAMETER         | REQUIRED | DESCRIPTION                                                                     | TYPE    | CONTAINS |
| ----------------- | -------- | ------------------------------------------------------------------------------- | ------- | -------- |
| **submit_id**     | required | Unique alphanumeric string that identifies the analysis results of a submission | string  |
| **poll**          | required | Would you like to poll the result?                                              | boolean |
| **poll_time_sec** | required | How long would you like to poll the request?                                    | numeric |

#### Action Output
| DATA PATH                                  | TYPE    | CONTAINS | EXAMPLE VALUES                       |
| ------------------------------------------ | ------- | -------- | ------------------------------------ |
| action_result.parameter.submit_id          | string  |          | 8559a7ce-2b85-451b-8742-4b943ad76a22 |
| action_result.sandbox_suspicious_list_resp | string  |          |                                      |
| action_result.status                       | string  |          | success  failed                      |
| action_result.message                      | string  |          |
| summary.total_objects                      | numeric |          |
| summary.total_objects_successful           | numeric |          |

## action: 'sandbox analysis result'
Displays the analysis results of the specified object.

Type: **investigate**  
Read only: **False**

Displays the analysis results of the specified object.

#### Action Parameters
| PARAMETER         | REQUIRED | DESCRIPTION                                                                     | TYPE    | CONTAINS |
| ----------------- | -------- | ------------------------------------------------------------------------------- | ------- | -------- |
| **report_id**     | required | Unique alphanumeric string that identifies the analysis results of a submission | string  |
| **poll**          | required | Would you like to poll the result?                                              | boolean |
| **poll_time_sec** | required | How long would you like to poll the request?                                    | numeric |

#### Action Output
| DATA PATH                             | TYPE    | CONTAINS | EXAMPLE VALUES                       |
| ------------------------------------- | ------- | -------- | ------------------------------------ |
| action_result.parameter.report_id     | string  |          | 8559a7ce-2b85-451b-8742-4b943ad76a22 |
| action_result.parameter.poll          | string  |          |                                      |
| action_result.parameter.poll_time_sec | numeric |          | 10                                   |
| action_result.analysis_result         | string  |          |
| action_result.message                 | string  |          |
| summary.total_objects                 | numeric |          |
| summary.total_objects_successful      | numeric |          |

## action: 'sandbox investigation package'
Downloads the Investigation Package of the specified object.

Type: **investigate**  
Read only: **False**

Downloads the Investigation Package of the specified object.

#### Action Parameters
| PARAMETER         | REQUIRED | DESCRIPTION                                                                     | TYPE    | CONTAINS |
| ----------------- | -------- | ------------------------------------------------------------------------------- | ------- | -------- |
| **submit_id**     | required | Unique alphanumeric string that identifies the analysis results of a submission | string  |
| **poll**          | required | Would you like to poll the result?                                              | boolean |
| **poll_time_sec** | required | How long would you like to poll the request?                                    | numeric |

#### Action Output
| DATA PATH                             | TYPE    | CONTAINS        | EXAMPLE VALUES                       |
| ------------------------------------- | ------- | --------------- | ------------------------------------ |
| action_result.parameter.submit_id     | string  |                 | 8559a7ce-2b85-451b-8742-4b943ad76a22 |
| action_result.parameter.poll          | string  |                 |                                      |
| action_result.parameter.poll_time_sec | numeric |                 | 10                                   |
| action_result.status                  | string  | success  failed |
| action_result.message                 | string  |                 |
| summary.total_objects                 | numeric |                 |
| summary.total_objects_successful      | numeric |                 |

## action: 'get suspicious list'
Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs in the Suspicious Object List and displays the information in a paginated list.

Type: **investigate**  
Read only: **True**

Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs in the Suspicious Object List and displays the information in a paginated list.

#### Action Output
| DATA PATH                        | TYPE    | CONTAINS        | EXAMPLE VALUES |
| -------------------------------- | ------- | --------------- | -------------- |
| action_result.status             | string  | success  failed |
| action_result.message            | string  |                 |
| summary.total_objects            | numeric |                 |
| summary.total_objects_successful | numeric |                 |

## action: 'get exception list'
Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs in the Exception List and displays it in a paginated list.

Type: **investigate**  
Read only: **True**

Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs in the Exception List and displays it in a paginated list.

#### Action Output
| DATA PATH                        | TYPE    | CONTAINS        | EXAMPLE VALUES |
| -------------------------------- | ------- | --------------- | -------------- |
| action_result.status             | string  | success  failed |
| action_result.message            | string  |                 |
| summary.total_objects            | numeric |                 |
| summary.total_objects_successful | numeric |                 |