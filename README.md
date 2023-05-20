[comment]: # "Auto-generated SOAR connector documentation"
# Trend Micro Vision One for Splunk SOAR

Publisher: Trend Micro  
Connector Version: 1.1.1  
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
|--------------|--------------------|------|
| https        | tcp                | 443  |

### Configuration Variables

The below configuration variables are required for this Connector to operate. These variables are
specified when configuring a Trend Micro Vision One asset in SOAR.

| VARIABLE    | REQUIRED | TYPE     | DESCRIPTION                   |
|-------------|----------|----------|-------------------------------|
| **api_url** | required | string   | The URL for your ETP instance |
| **api_key** | required | password | API key                       |

## Configure Trend Micro Vision One on Splunk SOAR

1.  Navigate to **Apps** \> **Unconfigured Apps** .
2.  Search for Trend Micro Vision One.
3.  Click **CONFIGURE NEW ASSET** to create and configure a new integration instance.
4.  ALternatively click on **INSTALL APP** and drop a tarball of the app

| **Parameter**              | **Description**                                                      | **Required** |
|----------------------------|----------------------------------------------------------------------|--------------|
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

1.  `      add to block list     `

#### Input

| **Argument Name** | **Description**                                              | **Required** |
|-------------------|--------------------------------------------------------------|--------------|
| value_type        | "file_sha1", "ip", "domain", "url" or "mailbox"              | Required     |
| target_value      | The object you would like to add that matches the value-type | Required     |
| product_id        | Target product                                               | Optional     |
| description       | Description                                                  | Optional     |

#### Context Output

| **Path**                       | **Type** | **Description**         |
|--------------------------------|----------|-------------------------|
| VisionOne.BlockList.actionId   | String   | The action id           |
| VisionOne.BlockList.taskStatus | String   | Status of existing task |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter.

1.  `      remove from block list     `

#### Input

| **Argument Name** | **Description**                                              | **Required** |
|-------------------|--------------------------------------------------------------|--------------|
| value_type        | "file_sha1", "ip", "domain", "url" or "mailbox"              | Required     |
| target_value      | The object you would like to add that matches the value-type | Required     |
| product_id        | Target product                                               | Optional     |
| description       | Description                                                  | Optional     |

#### Context Output

| **Path**                       | **Type** | **Description**         |
|--------------------------------|----------|-------------------------|
| VisionOne.BlockList.actionId   | String   | The action id           |
| VisionOne.BlockList.taskStatus | String   | Status of existing task |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter.

1.  `      quarantine email message     `

#### Input

| **Argument Name**     | **Description**                                                    | **Required** |
|-----------------------|--------------------------------------------------------------------|--------------|
| message_id            | Email Message ID from Trend Micro Vision One message activity data | Required     |
| mail_box              | Email mailbox where the message will be quarantied from            | Required     |
| message_delivery_time | Email message's original delivery time                             | Required     |
| product_id            | Target product                                                     | Optional     |
| description           | Description                                                        | Optional     |

#### Context Output

| **Path**                   | **Type** | **Description**         |
|----------------------------|----------|-------------------------|
| VisionOne.Email.actionId   | String   | The action id           |
| VisionOne.Email.taskStatus | String   | Status of existing task |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter.

1.  `      delete email message     `

#### Input

| **Argument Name**     | **Description**                                                    | **Required** |
|-----------------------|--------------------------------------------------------------------|--------------|
| message_id            | Email Message ID from Trend Micro Vision One message activity data | Required     |
| mail_box              | Email mailbox where the message will be deleted from               | Required     |
| message_delivery_time | Email message's original delivery time                             | Required     |
| product_id            | Target product                                                     | Optional     |
| description           | Description                                                        | Optional     |

#### Context Output

| **Path**                   | **Type** | **Description**         |
|----------------------------|----------|-------------------------|
| VisionOne.Email.actionId   | String   | The action id           |
| VisionOne.Email.taskStatus | String   | Status of existing task |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter.

1.  `      quarantine device     `

#### Input

| **Argument Name** | **Description**                                          | **Required** |
|-------------------|----------------------------------------------------------|--------------|
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to isolate | Required     |
| product_id        | Target product: "sao" or "sds". Default: "sao".          | Required     |
| description       | Description                                              | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**         |
|------------------------------------------|----------|-------------------------|
| VisionOne.Endpoint_Connection.actionId   | String   | The action id           |
| VisionOne.Endpoint_Connection.taskStatus | String   | Status of existing task |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`     20 minutes    ` .

1.  `      unquarantine device     `

#### Input

| **Argument Name** | **Description**                                                       | **Required** |
|-------------------|-----------------------------------------------------------------------|--------------|
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to restore connectivity | Required     |
| product_id        | Target product: "sao" or "sds". Default: "sao".                       | Required     |
| description       | Description                                                           | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**         |
|------------------------------------------|----------|-------------------------|
| VisionOne.Endpoint_Connection.actionId   | String   | The action id           |
| VisionOne.Endpoint_Connection.taskStatus | String   | Status of existing task |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`     20 minutes    ` .

1.  `      add to exception list     `

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                            | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| type              | The object type: "domain", "ip", "sha1", or "url"                                                                                                                                                                                                                                                                                                                                                                          | Required     |
| value             | Full and partial matches supported. Domain partial match, (with a wildcard as the subdomain, example, .example.com) IP partial match, (IP range example, 192.168.35.1-192.168.35.254, cidr example, 192.168.35.1/24) URL partial match, (Supports wildcards 'http://.'', 'https://.'' at beginning, or ''' at the end. Multiple wild cards also supported, such as , <https://.example.com/path1/> ) SHA1 only full match" | Required     |
| description       | Description                                                                                                                                                                                                                                                                                                                                                                                                                | Optional     |

#### Context Output

| **Path**                             | **Type** | **Description**                                |
|--------------------------------------|----------|------------------------------------------------|
| VisionOne.Exception_List.message     | String   | Status message of existing task                |
| VisionOne.Exception_List.status_code | String   | Response code of existing task                 |
| VisionOne.Exception_List.total_items | String   | Number of items present in the exception list. |

1.  `      delete from exception list     `

#### Input

| **Argument Name** | **Description**                                   | **Required** |
|-------------------|---------------------------------------------------|--------------|
| type              | The object type: "domain", "ip", "sha1", or "url" | Required     |
| value             | The object value                                  | Required     |
| description       | Description                                       | Optional     |

#### Context Output

| **Path**                             | **Type** | **Description**                                |
|--------------------------------------|----------|------------------------------------------------|
| VisionOne.Exception_List.message     | String   | Status message of existing task                |
| VisionOne.Exception_List.status_code | String   | Response code of existing task                 |
| VisionOne.Exception_List.total_items | String   | Number of items present in the exception list. |

1.  `      add to suspicious list     `

#### Input

| **Argument Name** | **Description**                                                                                                                                                             | **Required** |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| type              | The object type: "domain", "ip", "sha1", or "url"                                                                                                                           | Required     |
| value             | The object value                                                                                                                                                            | Required     |
| description       | Description                                                                                                                                                                 | Optional     |
| scan_action       | The action to take if object is found. If you don't use this parameter, the scan action specified in default_settings.riskLevel.type will be used instead. "block" or "log" | Optional     |
| risk_level        | The Suspicious Object risk level. If you don't use this parameter, high will be used instead. "high", "medium", or "low"                                                    | Optional     |
| expiry (days)     | The number of days to keep the object in the Suspicious Object List. If you don't use this parameter, the default_settings.expiredDay scan action will be used instead.     | Optional     |

#### Context Output

| **Path**                              | **Type** | **Description**                                |
|---------------------------------------|----------|------------------------------------------------|
| VisionOne.Suspicious_List.message     | String   | Status message of existing task                |
| VisionOne.Suspicious_List.status_code | String   | Response code of existing task                 |
| VisionOne.Suspicious_List.total_items | String   | Number of items present in the exception list. |

1.  `      delete from suspicious list     `

#### Input

| **Argument Name** | **Description**                                   | **Required** |
|-------------------|---------------------------------------------------|--------------|
| type              | The object type: "domain", "ip", "sha1", or "url" | Required     |
| value             | The object value                                  | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**                                |
|---------------------------------------|----------|------------------------------------------------|
| VisionOne.Suspicious_List.message     | String   | Status message of existing task                |
| VisionOne.Suspicious_List.status_code | String   | Response code of existing task                 |
| VisionOne.Suspicious_List.total_items | String   | Number of items present in the exception list. |

1.  `      terminate process     `

| **Argument Name** | **Description**                                                       | **Required** |
|-------------------|-----------------------------------------------------------------------|--------------|
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to terminate process on | Required     |
| file_sha1         | SHA1 hash of the process to terminate                                 | Required     |
| product_id        | Target product. Default: "sao"                                        | Optional     |
| description       | Description                                                           | Optional     |
| filename          | Optional file name list for log                                       | Optional     |

#### Context Output

| **Path**                               | **Type** | **Description**         |
|----------------------------------------|----------|-------------------------|
| VisionOne.Terminate_Process.actionId   | String   | The action id           |
| VisionOne.Terminate_Process.taskStatus | String   | Status of existing task |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout is
`     20 minutes    ` .

1.  `      get file analysis status     `

| **Argument Name** | **Description**                                                             | **Required** |
|-------------------|-----------------------------------------------------------------------------|--------------|
| task_id           | task_id from the trendmicro-visionone-submit-file-to-sandbox command output | Required     |

#### Context Output

| **Path**                                                | **Type** | **Description**         |
|---------------------------------------------------------|----------|-------------------------|
| VisionOne.File_Analysis_Status.message                  | String   | Message status          |
| VisionOne.File_Analysis_Status.code                     | String   | Code status of the task |
| VisionOne.File_Analysis_Status.task_id                  | String   | Task id                 |
| VisionOne.File_Analysis_Status.taskStatus               | String   | Task status             |
| VisionOne.File_Analysis_Status.digest                   | String   | Hash value of task      |
| VisionOne.File_Analysis_Status.analysis_completion_time | String   | Task completion time    |
| VisionOne.File_Analysis_Status.risk_level               | String   | Risk level of task      |
| VisionOne.File_Analysis_Status.description              | String   | Description of task     |
| VisionOne.File_Analysis_Status.detection_name_list      | String   | List of task detected   |
| VisionOne.File_Analysis_Status.threat_type_list         | String   | Threat type list        |
| VisionOne.File_Analysis_Status.file_type                | String   | Type of file            |
| VisionOne.File_Analysis_Status.report_id                | String   | Report ID of task.      |

1.  `      get file analysis report     `

| **Argument Name** | **Description**                                                                                              | **Required** |
|-------------------|--------------------------------------------------------------------------------------------------------------|--------------|
| report_id         | report_id of the sandbox submission retrieved from the trendmicro-visionone-get-file-analysis-status command | Required     |
| type              | Type of report to retrieve: "vaReport", "investigationPackage", or "suspiciousObject"                        | Required     |

#### Context Output

| **Path**                                                | **Type** | **Description**               |
|---------------------------------------------------------|----------|-------------------------------|
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
|-------------------|--------------------------------------------------------------------|--------------|
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to collect file from | Required     |
| product_id        | Product: "sao" "xes" "sds"                                         | Required     |
| file_path         | Path of the forensic file to collect                               | Required     |
| os                | "windows", "mac" or "linux"                                        | Required     |
| description       | Description of file collected                                      | Optional     |

#### Context Output

| **Path**                                   | **Type** | **Description**               |
|--------------------------------------------|----------|-------------------------------|
| VisionOne.Collect_Forensic_File.actionId   | String   | Action id of the running task |
| VisionOne.Collect_Forensic_File.taskStatus | String   | Status of the running task    |

Note: To get the complete task status run polling command `     status check    ` giving
`     actionId    ` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`     20 minutes    ` .

1.  `      download information collected file     `

| **Argument Name** | **Description**                                                   | **Required** |
|-------------------|-------------------------------------------------------------------|--------------|
| actionId          | actionId output from the collect command used to collect the file | Required     |

#### Context Output

| **Path**                                                            | **Type** | **Description**                                  |
|---------------------------------------------------------------------|----------|--------------------------------------------------|
| VisionOne.Download_Information_For_Collected_Forensic_File.url      | String   | URL of the collected file                        |
| VisionOne.Download_Information_For_Collected_Forensic_File.expires  | String   | URL expiration date                              |
| VisionOne.Download_Information_For_Collected_Forensic_File.password | String   | Archive password for the protected forensic file |
| VisionOne.Download_Information_For_Collected_Forensic_File.filename | String   | Name of the collected file                       |

Note: The URL received from the
'trendmicro-visionone-download-information-for-collected-forensic-file' will be valid for only
`     60 seconds    `

1.  `      submit file to sandbox     `

| **Argument Name** | **Description**                                                                                                                                   | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| file_url          | URL pointing to the location of the file to be submitted.                                                                                         | Required     |
| filename          | Name of the file to be analyzed.                                                                                                                  | Required     |
| document_password | The password for decrypting the submitted document. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding. | Optional     |
| archive_password  | The password for decrypting the submitted archive. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding.  | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**                    |
|------------------------------------------|----------|------------------------------------|
| VisionOne.Submit_File_to_Sandbox.message | String   | Message status of the sandbox file |
| VisionOne.Submit_File_to_Sandbox.code    | String   | Code status of the sandbox file    |
| VisionOne.Submit_File_to_Sandbox.task_id | String   | Task ID of the running task        |
| VisionOne.Submit_File_to_Sandbox.digest  | Object   | Sha value of the file              |

1.  `      status check     `

| **Argument Name** | **Description**                                            | **Required** |
|-------------------|------------------------------------------------------------|--------------|
| actionId          | Action ID of the task you would like to get the status of. | Required     |

#### Context Output

| **Path**                                 | **Type** | **Description**         |
|------------------------------------------|----------|-------------------------|
| VisionOne.Endpoint_Connection.actionId   | String   | The action id           |
| VisionOne.Endpoint_Connection.taskStatus | String   | Status of existing task |

1.  `      get endpoint info     `

| **Argument Name** | **Description**                                        | **Required** |
|-------------------|--------------------------------------------------------|--------------|
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to query | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**                                                  |
|---------------------------------------|----------|------------------------------------------------------------------|
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
|---------------------------------------|-------------------------------------------------|--------------|
| source data identifier (workbench id) | Workbench id of security incident in Vision One | Required     |
| content                               | note to be added to the workbench event         | Required     |

#### Context Output

| **Path**                         | **Type** | **Description**                               |
|----------------------------------|----------|-----------------------------------------------|
| VisionOne.Add_Note.Workbench_Id  | String   | Workbench ID that the action was executed on. |
| VisionOne.Add_Note.noteId        | String   | Note ID.                                      |
| VisionOne.Add_Note.response_code | String   | Response code for the request.                |
| VisionOne.Add_Note.response_msg  | String   | Response message for the request.             |

1.  `      update status     `

| **Argument Name**                     | **Description**                                                                                                | **Required** |
|---------------------------------------|----------------------------------------------------------------------------------------------------------------|--------------|
| source data identifier (workbench_id) | The ID of the workbench alert that you would like to update the status for.                                    | Required     |
| status                                | The status to assign to the workbench alert: new, in_progress, resolved_false_positive, resolved_true_positive | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**                               |
|---------------------------------------|----------|-----------------------------------------------|
| VisionOne.Update_Status.Workbench_Id  | String   | Workbench ID that the action was executed on. |
| VisionOne.Update_Status.response_code | String   | Response code for the request.                |
| VisionOne.Update_Status.response_msg  | String   | Response message for the request.             |

This version of the Trend Micro app is compatible with Splunk SOAR version **5.1.0** and above.

## Authentication Information

The app uses HTTPS protocol for communicating with the Trend Micro Vision One server. For
authentication a Vision One API Token is used by the Splunk SOAR Connector.

----------------------------------------------------------------------------------------------------

[View Integration
Documentation](insert%20here%20link%20to%20documentation%20that%20will%20be%20published%20on%20Splunk%20docs)


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a VisionOne asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_url** |  required  | string | Vision One API URL (e.g. https://api.xdr.trendmicro.com)
**api_key** |  required  | password | Vision One API Token

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
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname_mac** |  required  | Hostname/IP/MAC of the endpoint to query (Required) | string |  `ip`  `mac address`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.status | string |  |  
action_result.data.\*.errorCode | string |  |  
action_result.data.\*.result.logonAccount.value | string |  |  
action_result.data.\*.result.hostname.value | string |  |  
action_result.data.\*.result.macAddr.value | string |  `mac address`  |  
action_result.data.\*.result.ip.value | string |  `ip`  |  
action_result.data.\*.result.osName | string |  |  
action_result.data.\*.result.osVersion | string |  |  
action_result.data.\*.result.osDescription | string |  |  
action_result.data.\*.result.productCode | string |  |  
action_result.parameter.ip_hostname_mac | string |  `ip`  `mac address`  `host name`  |  
action_result.status | string |  |   success  failed 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'quarantine device'
Quarantine the endpoint

Type: **contain**  
Read only: **False**

Quarantine the endpoint.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname_mac** |  required  | Hostname/IP/MAC of endpoint to quarantine/isolate (Required) | string |  `ip`  `mac address`  `host name` 
**productid** |  required  | Trend Micro product ID for quarantine task. 'sao' or 'sds'. Default: 'sao' (Required) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.actionId | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname_mac | string |  `ip`  `mac address`  `host name`  |  
action_result.parameter.productid | string |  |  
action_result.parameter.description | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'unquarantine device'
Unquarantine the endpoint

Type: **correct**  
Read only: **False**

Unquarantine the endpoint.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname_mac** |  required  | Hostname/IP/MAC of endpoint to unquarantine/restore connectivity for (Required) | string |  `ip`  `mac address`  `host name` 
**productid** |  required  | Trend Micro product ID for unquarantine task. 'sao' or 'sds'. Default: 'sao' (Required) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.actionId | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname_mac | string |  `ip`  `mac address`  `host name`  |  
action_result.parameter.productid | string |  |  
action_result.parameter.description | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'on poll'
Callback action for the on_poll ingest functionality

Type: **ingest**  
Read only: **True**

Callback action for the on_poll ingest functionality.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**starttime** |  optional  | Make sure time format matches following example (2020-06-15T10:00:00.000Z) | string | 
**endtime** |  optional  | Make sure time format matches following example (2020-06-15T12:00:00.000Z) | string | 
**limit** |  optional  | Limit of polling results. Default: limit=100 | numeric | 

#### Action Output
No Output  

## action: 'status check'
Checks the status of a task

Type: **investigate**  
Read only: **False**

Checks the status of a particular task.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_id** |  required  | Action ID of the task you would like to get the status of (Required) | string |  `action id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.action_id | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'add to blocklist'
Adds an item to the Suspicious Objects list in Vision One

Type: **contain**  
Read only: **False**

Adds an item from the Trend Micro Vision One Suspicious Objects list.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**value_type** |  required  | Type of object to be added ('domain', 'ip', 'sha1', or 'url') (Required) | string | 
**target_value** |  required  | The object you would like to add to the block list that matches the value-type (Required) | string | 
**product_id** |  optional  | Trend Micro ID of product (Optional) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.actionId | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.description | string |  |  
action_result.parameter.product_id | string |  |  
action_result.parameter.target_value | string |  |  
action_result.parameter.value_type | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'remove from blocklist'
Removes an item from the Suspicious Objects list

Type: **correct**  
Read only: **False**

Removes an item from the Trend Micro Vision One Suspicious Objects list.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**value_type** |  required  | Type of object to be removed ('domain', 'ip', 'sha1', or 'url') (Required) | string | 
**target_value** |  required  | The object you would like to remove from block list that matches the value-type (Required) | string | 
**product_id** |  optional  | Trend Micro ID of product (Optional) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.actionId | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.description | string |  |  
action_result.parameter.product_id | string |  |  
action_result.parameter.target_value | string |  |  
action_result.parameter.value_type | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'quarantine email message'
Quarantine the email message

Type: **contain**  
Read only: **False**

Retrieve data from the quarantine email message and send the result to dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** |  required  | Email Message ID from Trend Micro Vision One message activity data (Required) | string | 
**mailbox** |  required  | Email mailbox where the message will be quarantied from (Required) | string | 
**message_delivery_time** |  optional  | Email message's original delivery time (format=YYYY-MM-DDTHH:MM:SS.000Z) (Required) | string | 
**product_id** |  optional  | Target product ID (Optional) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.actionId | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.message_id | string |  |  
action_result.parameter.mailbox | string |  |  
action_result.parameter.message_delivery_time | string |  |  
action_result.parameter.product_id | string |  |  
action_result.parameter.description | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'delete email message'
Delete the email message

Type: **correct**  
Read only: **False**

Retrieve data from the delete email message and relay result to Splunk.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** |  required  | Email Message ID from Trend Micro Vision One message activity data (Required) | string | 
**mailbox** |  required  | Email mailbox where the message will be deleted from (Required) | string | 
**message_delivery_time** |  optional  | Email message's original delivery time (format=YYYY-MM-DDTHH:MM:SS.000Z) (Required) | string | 
**product_id** |  optional  | Target product ID (Optional) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.actionId | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.message_id | string |  |  
action_result.parameter.mailbox | string |  |  
action_result.parameter.message_delivery_time | string |  |  
action_result.parameter.product_id | string |  |  
action_result.parameter.description | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'terminate process'
Terminate the process running on the endpoint

Type: **contain**  
Read only: **False**

Terminate the process running on the endpoint and send results to the dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname_mac** |  required  | Hostname, macaddr or ip of the endpoint to terminate process on (Required) | string | 
**product_id** |  optional  | Target product. Default: 'sao' (Optional) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 
**file_sha1** |  required  | SHA1 hash of the process to terminate (Required) | string | 
**filename** |  optional  | File name for log (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.actionId | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname_mac | string |  |  
action_result.parameter.product_id | string |  |  
action_result.parameter.description | string |  |  
action_result.parameter.file_sha1 | string |  |  
action_result.parameter.filename | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'add to exception'
Add object to exception list

Type: **correct**  
Read only: **False**

Add the exception object to the exception list and send the result to Splunk.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**type** |  required  | The object type: 'domain', 'ip', 'sha1', or 'url' (Required) | string | 
**value** |  required  | Full and partial matches supported. Domain partial match, (with a wildcard as the subdomain, example, .example.com) IP partial match, (IP range example, 192.168.35.1-192.168.35.254, cidr example, 192.168.35.1/24) URL partial match, (Supports wildcards 'http://.'', 'https://.'' at beginning, or ''' at the end. Multiple wild cards also supported, such as , https://.example.com/path1/) SHA1 only full match (Required) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.message | string |  |  
action_result.data.\*.status_code | string |  |  
action_result.data.\*.total_items | numeric |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.description | string |  |  
action_result.parameter.type | string |  |  
action_result.parameter.value | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'delete from exception'
Delete object from exception list

Type: **correct**  
Read only: **False**

Delete the exception object from the exception list and relay data to Splunk.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**type** |  required  | The object type: 'domain', 'ip', 'sha1', or 'url' (Required) | string | 
**value** |  required  | The object value (Required) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.message | string |  |  
action_result.data.\*.status_code | string |  |  
action_result.data.\*.total_items | numeric |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.description | string |  |  
action_result.parameter.type | string |  |  
action_result.parameter.value | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'add to suspicious'
Add suspicious object to suspicious list

Type: **contain**  
Read only: **False**

Add suspicious object to suspicious list and send the result to dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**type** |  required  | The object type: 'domain', 'ip', 'sha1', or 'url' (Required) | string | 
**value** |  required  | The object value (Required) | string | 
**description** |  optional  | Description for this activity (Optional) | string | 
**scan_action** |  optional  | The action to take if object is found. If you don't use this parameter, the scan action specified in default_settings.riskLevel.type will be used instead. 'block' or 'log' (Optional) | string | 
**risk_level** |  optional  | The Suspicious Object risk level. If you don't use this parameter, high will be used instead. risk level (either 'high', 'medium' or 'low') (Optional) | string | 
**expiry** |  optional  | The number of days to keep the object in the Suspicious Object List. If you don't use this parameter, the default_settings.expiredDay scan action will be used instead (Optional) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.message | string |  |  
action_result.data.\*.status_code | string |  |  
action_result.data.\*.total_items | numeric |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.description | string |  |  
action_result.parameter.type | string |  |  
action_result.parameter.value | string |  |  
action_result.parameter.scan_action | string |  |  
action_result.parameter.risk_level | string |  |  
action_result.parameter.expiry | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'delete from suspicious'
Delete the suspicious object from suspicious list

Type: **correct**  
Read only: **False**

Delete the suspicious object from suspicious list and send the result to the dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**type** |  required  | The object type: 'domain', 'ip', 'sha1', or 'url' (Required) | string | 
**value** |  required  | The object value (Required) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.message | string |  |  
action_result.data.\*.status_code | string |  |  
action_result.data.\*.total_items | numeric |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.type | string |  |  
action_result.parameter.value | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'check analysis status'
Get the status of file analysis based on task id

Type: **investigate**  
Read only: **False**

Get the status of file analysis based on task id and send result to the dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**task_id** |  required  | Task_id from the trendmicro-visionone-start-analysis command output. Submission ID in Vision One (Required) | string |  `task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.message | string |  |  
action_result.data.\*.code | string |  |  
action_result.data.\*.data.taskId | string |  `task id`  |  
action_result.data.\*.data.taskStatus | string |  |  
action_result.data.\*.data.digest | string |  |  
action_result.data.\*.data.analysisSummary.analysisCompletionTime | string |  |  
action_result.data.\*.data.analysisSummary.riskLevel | string |  |  
action_result.data.\*.data.analysisSummary.description | string |  |  
action_result.data.\*.data.analysisSummary.detectionNameList | string |  |  
action_result.data.\*.data.analysisSummary.threatTypeList | string |  |  
action_result.data.\*.data.analysisSummary.trueFileType | string |  |  
action_result.data.\*.data.reportId | numeric |  `report id`  |  
action_result.status | string |  |   success  failed 
action_result.parameter.task_id | string |  `task id`  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'download analysis report'
Get the analysis report of a file based on report id

Type: **investigate**  
Read only: **False**

Get the analysis report of a file based on report id and send the results to the dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** |  required  | Report_id of the sandbox submission retrieved from the trendmicro-visionone-check-analysis-status command (Required) | string | 
**type** |  required  | Type of report to retrieve: 'vaReport', 'nvestigationPackage', or 'suspiciousObject' (Required) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.report_id | string |  |  
action_result.parameter.type | string |  |  
action_result.status | string |  |   success  failed 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'collect forensic file'
Collect forensic file

Type: **investigate**  
Read only: **False**

Collect forensic file and send result to the dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname_mac** |  required  | IP/Hostname/MAC address of the endpoint to collect file from (Required) | string | 
**product_id** |  required  | Product: 'sao' 'xes' 'sds' (Required) | string | 
**description** |  optional  | Description of file collected (Optional) | string | 
**file_path** |  required  | Path of the forensic file to collect (Required) | string | 
**os** |  optional  | OS type (mac, windows or linux without version numbers) (Required) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.actionId | string |  `action id`  |  
action_result.data.\*.taskStatus | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname_mac | string |  |  
action_result.parameter.product_id | string |  |  
action_result.parameter.description | string |  |  
action_result.parameter.file_path | string |  |  
action_result.parameter.os | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'forensic file info'
Get the download information for collected forensic file

Type: **investigate**  
Read only: **False**

Get the download information for collected forensic file and send the result to the dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_id** |  required  | ActionId output from the collect command used to collect the file (Required) | string |  `action id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.data.url | string |  `file url`  `url`  |  
action_result.data.\*.data.expires | string |  |  
action_result.data.\*.data.password | string |  `document pass`  `archive pass`  |  
action_result.data.\*.data.filename | string |  `file name`  |  
action_result.parameter.action_id | string |  `action id`  |  
action_result.status | string |  |   success  failed 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'start analysis'
Submit file to sandbox for analysis

Type: **investigate**  
Read only: **False**

Submit file to sandbox for analysis and send the result to the dashboard.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file_url** |  required  | URL pointing to the location of the file to be submitted (Required) | string | 
**file_name** |  required  | Name of the file to be analyzed (Required) | string | 
**document_pass** |  optional  | The password for decrypting the submitted document. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding (Optional) | string | 
**archive_pass** |  optional  | The password for decrypting the submitted archive. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding (Optional) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.code | string |  |  
action_result.data.\*.message | string |  |  
action_result.data.\*.data.taskId | string |  `task id`  |  
action_result.data.\*.data.digest | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.file_url | string |  |  
action_result.parameter.file_name | string |  |  
action_result.parameter.document_pass | string |  |  
action_result.parameter.archive_pass | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'add note'
Adds a note to an existing workbench alert

Type: **generic**  
Read only: **False**

Adds a note to an existing workbench alert in Trend Micro Vision One.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**workbench_id** |  required  | Workbench id of security incident in Vision One (Required) | string |  `source data identifier` 
**content** |  required  | Note to be added to workbench event (Required) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.info.code | string |  |  
action_result.data.\*.info.msg | string |  |  
action_result.data.\*.data.id | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.workbench_id | string |  `source data identifier`  |  
action_result.parameter.content | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'update status'
Updates the status of an existing workbench alert

Type: **correct**  
Read only: **False**

Updates the status of an existing workbench alert in Trend Micro Vision One.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**workbench_id** |  required  | The ID of the workbench alert that you would like to update the status for (Required) | string |  `source data identifier` 
**status** |  required  | The status to assign to the workbench alert: new, in_progress, resolved_false_positive, resolved_true_positive (Required) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.info.code | string |  |  
action_result.data.\*.info.msg | string |  |  
action_result.data.\*.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.parameter.workbench_id | string |  `source data identifier`  |  
action_result.parameter.status | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  