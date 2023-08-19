
# Trend Micro Vision One for Splunk SOAR

Publisher: Trend Micro  
Connector Version: 1.1.1  
Product Vendor: Trend Micro  
Product Name: VisionOne  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection


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

- **Email** : <integrations@trendmicro.com>

----------------------------------------------------------------------------------------------------

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

1. Navigate to **Apps** \> **Unconfigured Apps** .
2. Search for Trend Micro Vision One.
3. Click **CONFIGURE NEW ASSET** to create and configure a new integration instance.
4. ALternatively click on **INSTALL APP** and drop a tarball of the app

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

1. Click **TEST CONNECTIVITY** to validate the URLs, token, and connection.

### Supported Actions  

[Test Connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[Get Endpoint Info](#action-get-endpoint-info) - Gather information about an endpoint  
[Quarantine Device](#action-quarantine-device) - Quarantine the endpoint  
[Unquarantine Device](#action-unquarantine-device) - Unquarantine the endpoint  
[On Poll](#action-on-poll) - Callback action for the on_poll ingest functionality  
[Status Check](#action-status-check) - Checks the status of a task  
[Add To Blocklist](#action-add-to-blocklist) - Adds an item to the Suspicious Objects list in Vision One  
[Remove From Blocklist](#action-remove-from-blocklist) - Removes an item from the Suspicious Objects list  
[Quarantine Email Message](#action-quarantine-email-message) - Quarantine the email message  
[Delete Email Message](#action-delete-email-message) - Delete the email message  
[Terminate Process](#action-terminate-process) - Terminate the process running on the endpoint  
[Add To Exception](#action-add-to-exception) - Add object to exception list  
[Delete From Exception](#action-delete-from-exception) - Delete object from exception list  
[Add To Suspicious](#action-add-to-suspicious) - Add suspicious object to suspicious list  
[Delete From Suspicious](#action-delete-from-suspicious) - Delete the suspicious object from suspicious list  
[Check Analysis Status](#action-check-analysis-status) - Get the status of file analysis based on task id  
[Download Analysis Report](#action-download-analysis-report) - Get the analysis report of a file based on report id  
[Collect Forensic File](#action-collect-forensic-file) - Collect forensic file  
[Forensic File Info](#action-forensic-file-info) - Get the download information for collected forensic file  
[Start Analysis](#action-start-analysis) - Submit file to sandbox for analysis. For supported file types, check [here](https://docs.trendmicro.com/en-us/enterprise/trend-vision-one-olh/threat-intelligence-/sandbox-analysis/sandbox-supported-fi.aspx)  
[Add Note](#action-add-note) - Adds a note to an existing workbench alert  
[Update Status](#action-update-status) - Updates the status of an existing workbench alert  
[Get Alert Details](#action-get-alert-details) - Displays information about the specified alert  
[Urls To Sandbox](#action-urls-to-sandbox) - Submits URLs to the sandbox for analysis  
[Enable Account](#action-enable-account) - Allows the user to sign in to new application and browser sessions  
[Disable Account](#action-disable-account) - Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session  
[Restore Email Message](#action-restore-email-message) - Restore quarantined email messages  
[Sign Out Account](#action-sign-out-account) - Signs the user out of all active application and browser sessions  
[Force Password Reset](#action-force-password-reset) - Signs the user out of all active application and browser sessions, and forces the user to create a new password during the next sign-in attempt  
[Sandbox Suspicious List](#action-sandbox-suspicious-list) - Downloads the suspicious object list associated to the specified object  
[Sandbox Analysis Result](#action-sandbox-analysis-result) - Displays the analysis results of the specified object  
[Sandbox Investigation Package](#action-sandbox-investigation-package) - Downloads the Investigation Package of the specified object  
[Get Suspicious List](#action-get-suspicious-list) - Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs in the Suspicious Object List and displays the information in a paginated list  
[Get Exception List](#action-get-exception-list) - Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs in the Exception List and displays it in a paginated list  

## Commands

You can execute these commands from the Splunk SOAR CLI, as part of an automation, or in a playbook.

## Action: 'Test Connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| N/A               |                 |              |

#### Context Output

| **Path** | **Type** | **Description** |
| -------- | -------- | --------------- |
| N/A      |          |                 |

## Action: 'Add To Blocklist'

Type: **contain**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and description | Required     |

Example input:

```
Block Objects
  [{
    "object_type": "ip",
    "object_value": "6.6.6.6",
    "description": "Block IP"
  },{
    "object_type": "domain",
    "object_value": "hello.com",
  }]
```

Note: `description` is optional and a default value is automatically provided.

#### Context Output

| **Path**                    | **Type** | **Description**                  |
| --------------------------- | -------- | -------------------------------- |
| VisionOne.BlockList.status  | Numeric  | HTTP status code for the action  |
| VisionOne.BlockList.task_id | String   | Task ID generated for the action |

Note: To get the complete task status run polling command `status check` giving
`taskId` as input parameter.

## Action: 'Remove From Blocklist'

Type: **correct**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and description | Required     |

Example input:

```
Block Objects
  [{
    "description": "Remove from blocklist",
    "object_type": "ip",
    "object_value": "6.6.6.3"
  }]
```

Note: `description` is optional and a default value is automatically provided.

#### Context Output

| **Path**                    | **Type** | **Description**                  |
| --------------------------- | -------- | -------------------------------- |
| VisionOne.BlockList.status  | Numeric  | HTTP status code for the action  |
| VisionOne.BlockList.task_id | String   | Task ID generated for the action |

Note: To get the complete task status run polling command `status check` giving
`taskId` as input parameter.

## Action: 'Quarantine Email Message'

Quarantine the email message

Type: **contain**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------- | ------------ |
| email_identifiers | Email Identifiers consisting of message id, mailbox and description | Required     |

Example input:

```
Email Identifiers
Call using Message ID.
  [{
    "description": "Quarantine email message",
    "mailbox": "jdoe@testemailtest.com",
    "message_id": "<AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0nNjgfLS2AABNpgTSQAA>"
  }]
Call using unique ID.
  [{
    "description": "Quarantine email message",
    "message_id": "AAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0"
  }]
```

Note: `description` is optional and a default value is automatically provided. If `Unique ID` is being passed then the `mailbox ID` is not needed.

#### Context Output

| **Path**                | **Type** | **Description**                                  |
| ----------------------- | -------- | ------------------------------------------------ |
| VisionOne.Email.status  | Numeric  | HTTP status code for the action                  |
| VisionOne.Email.task_id | String   | Task ID generated for quarantining email message |

Note: To get the complete task status run polling command `status check` giving
`taskId` as input parameter.

## Action: 'Delete Email Message'

Delete the email message.

Type: **correct**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------- | ------------ |
| email_identifiers | Email Identifiers consisting of message id, mailbox and description | Required     |

Example input:

```
Email Identifiers
Call using message ID.
  [{
    "description": "Delete email message",
    "mailbox": "jdoe@testemailtest.com",
    "message_id": "<AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0nNjgfLS2AABNpgTSQAA>"
  }]
Call using unique ID.
  [{
    "description": "Delete email message",
    "message_id": "AAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0"
  }]
```

Note: `description` is optional and a default value is automatically provided. If `Unique ID` is being passed then the `mailbox ID` is not needed, only pass one or the other.

#### Context Output

| **Path**                | **Type** | **Description**                              |
| ----------------------- | -------- | -------------------------------------------- |
| VisionOne.Email.status  | Numeric  | HTTP status code for the action              |
| VisionOne.Email.task_id | String   | Task ID generated for deleting email message |

Note: To get the complete task status run polling command `status check` giving
`taskId` as input parameter.

## Action: 'Quarantine Device'

Quarantine the endpoint.

Type: **contain**  
Read only: **False**

#### Input

| **Argument Name**    | **Description**                                                                    | **Required** |
| -------------------- | ---------------------------------------------------------------------------------- | ------------ |
| endpoint_identifiers | Endpoint Identifiers consisting of endpoint(hostname or agentGuid) and description | Required     |

Example input:

```
Endpoint Identifiers
  [{
    "endpoint": "endpoint123",
    "description": "Test quarantine device"
  }]
```

Note: `endpoint` accepts agentGuid or hostname. `description` is optional and a default value is automatically provided.

#### Context Output

| **Path**                              | **Type** | **Description**                             |
| ------------------------------------- | -------- | ------------------------------------------- |
| VisionOne.Endpoint_Connection.status  | Numeric  | HTTP status code for the action             |
| VisionOne.Endpoint_Connection.task_id | String   | Task ID generated for quarantining endpoint |

Note: To get the complete task status run polling command `status check` giving
`taskId` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`20 minutes` .

## Action: 'Unquarantine Device'

Restore the endpoint.

Type: **correct**  
Read only: **False**

#### Input

| **Argument Name**    | **Description**                                                                    | **Required** |
| -------------------- | ---------------------------------------------------------------------------------- | ------------ |
| endpoint_identifiers | Endpoint Identifiers consisting of endpoint(hostname or agentGuid) and description | Required     |

Example input:

```
Endpoint Identifiers
  [{
    "description": "Restore endpoint",
    "endpoint": "endpoint123"
  }]
```

Note: `endpoint` accepts agentGuid or hostname. `description` is optional and a default value is automatically provided.

#### Context Output

| **Path**                              | **Type** | **Description**                          |
| ------------------------------------- | -------- | ---------------------------------------- |
| VisionOne.Endpoint_Connection.status  | Numeric  | HTTP status code for the action          |
| VisionOne.Endpoint_Connection.task_id | String   | Task ID generated for restoring endpoint |

Note: To get the complete task status run polling command `status check` giving
`taskId` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`20 minutes` .

## Action: 'On Poll'

This polls information about workbench alerts that match the specified criteria in a paginated list.

Type: **ingest**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                                                                                                                                                                  | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| starttime         | Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the start of the data retrieval time range. The available oldest value is "1970-01-01T00:00:00Z"        | False        |
| endtime           | Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the end of the data retrieval time range. Ensure that "endDateTime" is not earlier than "startDateTime" | False        |

Example input:

```
Start Time
  2020-01-01T10:00:00Z
End Time
  2023-01-01T10:00:00Z
```

#### Context Output

| **Path**                            | **Type**            | **Description**                                  |
| ----------------------------------- | ------------------- | ------------------------------------------------ |
| VisionOne.On_Poll.serialized_alerts | []serialized_alerts | Array of alerts retrieved (awb-workbenchAlertV3) |

## Action: 'Add To Exception'

Add object to exception list.

Type: **correct**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                               | **Required** |
| ----------------- | --------------------------------------------- | ------------ |
| block_objects     | Object made up of type, value and description | Required     |

Example input:

```
Block Objects
  [{"object_type": "ip","object_value": "1.2.6.9", "description": "Add to exception list"},
  {"object_type": "ip","object_value": "1.1.1.1"}]
```

Note: `description` is optional and a default value is automatically provided.

#### Context Output

| **Path**                         | **Type** | **Description**                                |
| -------------------------------- | -------- | ---------------------------------------------- |
| VisionOne.Exception_List.status  | Numeric  | HTTP status code for the action                |
| VisionOne.Exception_List.task_id | String   | Task ID generated for adding to exception list |

## Action: 'Delete From Exception'

Delete object from exception list.

Type: **correct**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                               | **Required** |
| ----------------- | --------------------------------------------- | ------------ |
| block_objects     | Object made up of type, value and description | Required     |

Example input:

```
Block Objects
  [{
    "object_type": "ip",
    "object_value": "1.6.6.3"
  }]
```

#### Context Output

| **Path**                         | **Type** | **Description**                                           |
| -------------------------------- | -------- | --------------------------------------------------------- |
| VisionOne.Exception_List.status  | Numeric  | HTTP status code for the action                           |
| VisionOne.Exception_List.task_id | String   | Task ID generated after removing item from exception list |

## Action: 'Add To Suspicious'

Add suspicious object to suspicious list.

Type: **contain**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                                                                  | **Required** |
| ----------------- | -------------------------------------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and scan_action, risk_level and expiry_days | Required     |

Example input:

```
Block Objects
  [{
    "object_type": "ip",
    "risk_level": "high",
    "object_value": "6.6.6.3"
    "expiry_days": "30",
    "scan_action": "block",
  }]
```

#### Context Output

| **Path**                          | **Type** | **Description**                                        |
| --------------------------------- | -------- | ------------------------------------------------------ |
| VisionOne.Suspicious_List.status  | Numeric  | HTTP status code for the action                        |
| VisionOne.Suspicious_List.task_id | String   | Task ID generated after adding item to suspicious list |

## Action: 'Delete From Suspicious'

Delete the suspicious object from suspicious list.

Type: **correct**  
Read only: **False**

#### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| block_objects     | Object object made up of type, value and description | Required     |

Example input:

```
Block Objects
  [{
    "object_type": "ip",
    "object_value": "6.6.6.4"
  }]
```

#### Context Output

| **Path**                          | **Type** | **Description**                                            |
| --------------------------------- | -------- | ---------------------------------------------------------- |
| VisionOne.Suspicious_List.status  | Numeric  | HTTP status code for the action                            |
| VisionOne.Suspicious_List.task_id | String   | Task ID generated after removing item from suspicious list |

## Action: 'Terminate Process'

Terminate the process running on the endpoint.

Type: **contain**  
Read only: **False**

| **Argument Name**   | **Description**                                                                                                           | **Required** |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------ |
| process_identifiers | Process Identifiers consisting of endpoint(hostname or agentGuid), filesha1, filename(optional) and description(optional) | Required     |

Example input:

```
Process Identifiers
  [{
    "endpoint": "endpoint123",
    "file_sha1": "984afc7.......95b519a081321"
    "description": "terminate process",
    "filename": "exmaplename.txt"
  }]
```

Note: `description` is optional and a default value is provided.

#### Context Output

| **Path**                            | **Type** | **Description**                               |
| ----------------------------------- | -------- | --------------------------------------------- |
| VisionOne.Terminate_Process.status  | Numeric  | HTTP status code for the action               |
| VisionOne.Terminate_Process.task_id | String   | Task ID generated after terminating a process |

Note: To get the complete task status run polling command `status check` giving
`taskId` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout is
`20 minutes` .

## Action: 'Get Sandbox Submission status'

Get the status of file analysis based on task id.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                           | **Required** |
| ----------------- | ------------------------------------------------------------------------- | ------------ |
| task_id           | ID generated from the trendmicro-visionone-submit-file-to-sandbox command | Required     |

Example input:

```
Task ID
  012e4eac-9bd9-4e89-95db-77e02f75a6f3
```

#### Context Output

| **Path**                                                      | **Type** | **Description**                                                                                                                                                |
| ------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| VisionOne.Get_Sandbox_Submission_Status.id                    | String   | Unique alphanumeric string that identifies a submission                                                                                                        |
| VisionOne.Get_Sandbox_Submission_Status.status                | String   | Action applied to a submitted object. Possible values: succeeded, running, failed                                                                              |
| VisionOne.Get_Sandbox_Submission_Status.action                | String   | Action applied to a submitted object                                                                                                                           |
| VisionOne.Get_Sandbox_Submission_Status.error                 | String   | Error code and message for the submission                                                                                                                      |
| VisionOne.Get_Sandbox_Submission_Status.digest                | String   | The hash values for the file analyzed                                                                                                                          |
| VisionOne.Get_Sandbox_Submission_Status.created_date_time     | String   | Timestamp in ISO 8601 that indicates the object was submitted to the sandbox                                                                                   |
| VisionOne.Get_Sandbox_Submission_Status.last_action_date_time | String   | Timestamp in ISO 8601 format that indicates when the information about a submission was last updated                                                           |
| VisionOne.Get_Sandbox_Submission_Status.resource_location     | String   | Location of the submitted file                                                                                                                                 |
| VisionOne.Get_Sandbox_Submission_Status.is_cached             | Boolean  | Parameter that indicates if an object has been analyzed before by the Sandbox Analysis App. Submissions marked as cached do not count toward the daily reserve |
| VisionOne.Get_Sandbox_Submission_Status.arguments             | String   | Arguments for the file submitted                                                                                                                               |

## Action: 'Check Analysis Status'

This action retrieves the status of a sandbox submission analysis based on task_id.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                 | **Required** |
| ----------------- | ------------------------------------------------------------------------------- | ------------ |
| task_id           | Unique alphanumeric string that identifies the analysis results of a submission | Required     |

Example input:

```
Task ID
  8559a7ce-2b85-451b-8742-4b943ad76a22
```

#### Context Output

| **Path**                                              | **Type** | **Description**                                                                                                                                                |
| ----------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| VisionOne.Check_Analysis_Status.id                    | String   | Unique alphanumeric string that identifies a submission                                                                                                        |
| VisionOne.Check_Analysis_Status.status                | String   | Action applied to a submitted object. Possible values: succeeded, running, failed                                                                              |
| VisionOne.Check_Analysis_Status.created_date_time     | String   | Timestamp in ISO 8601 that indicates the object was submitted to the sandbox                                                                                   |
| VisionOne.Check_Analysis_Status.last_action_date_time | String   | Timestamp in ISO 8601 format that indicates when the information about a submission was last updated                                                           |
| VisionOne.Check_Analysis_Status.action                | String   | Action applied to a submitted object                                                                                                                           |
| VisionOne.Check_Analysis_Status.resource_location     | String   | Location of the submitted file                                                                                                                                 |
| VisionOne.Check_Analysis_Status.is_cached             | String   | Parameter that indicates if an object has been analyzed before by the Sandbox Analysis App. Submissions marked as cached do not count toward the daily reserve |
| VisionOne.Check_Analysis_Status.digest                | String   | The hash values for the file analyzed                                                                                                                          |
| VisionOne.Check_Analysis_Status.arguments             | String   | Arguments for the file submitted                                                                                                                               |
| VisionOne.Check_Analysis_Status.error                 | String   | Error code and message for the submission                                                                                                                      |

## Action: 'Download Analysis Report'

Get the analysis report of a file based on report id.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                                    | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------- | ------------ |
| submit_id         | Unique alphanumeric string that identifies the analysis results of a submission                    | Required     |
| poll              | If script should wait until the task is finished before returning the result (disabled by default) | Optional     |
| poll_time_sec     | Maximum time to wait for the result to be available                                                | Optional     |

Example input:

```
Submit ID
  8559a7ce-2b85-451b-8742-4b943ad76a22
Poll
  true
Poll Time Sec
  30
```

#### Context Output

| **Path**                                      | **Type** | **Description**                     |
| --------------------------------------------- | -------- | ----------------------------------- |
| VisionOne.Download_Analysis_Report.file_added | String   | Name of the PDF file added to Vault |

## Action: 'Collect Forensic File'

Collect forensic file.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                        | **Required** |
| ----------------- | ---------------------------------------------------------------------- | ------------ |
| collect_files     | Collect file input JSON containing endpoint, file path and description | Required     |

Example input:

```
Collect Files
  [{
    "endpoint": "endpoint123",
    "file_path": "C:/virus.exe",
    "description": "collect malicious file"
  }]
```

Note: `description` is optional and a default value is provided.

#### Context Output

| **Path**                                       | **Type**         | **Description**                                 |
| ---------------------------------------------- | ---------------- | ----------------------------------------------- |
| VisionOne.Collect_Forensic_File.multi_response | []multi_response | Response Array containing http code and task_id |

Note: To get the complete task status run polling command `status check` giving
`taskId` as input parameter. Note: The above command should be added with execution
timeout in the advanced field of playbook execution. The recommended timeout be
`20 minutes` .

## Action: 'Forensic File Info'

Get the download information for collected forensic file.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                                    | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------- | ------------ |
| task_id           | task_id output from the collect forensic file command used to collect the file                     | Required     |
| poll              | If script should wait until the task is finished before returning the result (disabled by default) | Optional     |
| poll_time_sec     | Maximum time to wait for the result to be available                                                | Optional     |

Example input:

```
Task ID
  00000012
Poll
  True
Poll Time Sec
  30
```

#### Context Output

| **Path**                                           | **Type** | **Description**                                                                                                  |
| -------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| VisionOne.Forensic_File_Info.id                    | String   | Unique numeric string that identifies a response task                                                            |
| VisionOne.Forensic_File_Info.status                | String   | The status of the command sent to the managing server. Possible task statuses: queued, running,succeeded, failed |
| VisionOne.Forensic_File_Info.created_date_time     | String   | Task completion time                                                                                             |
| VisionOne.Forensic_File_Info.last_action_date_time | String   | Timestamp in ISO 8601 format that indicates when the information about a submission was last updated             |
| VisionOne.Forensic_File_Info.action                | String   | Action applied to a submitted object                                                                             |
| VisionOne.Forensic_File_Info.description           | String   | Description of a response task                                                                                   |
| VisionOne.Forensic_File_Info.account               | String   | User that triggered the response                                                                                 |

Note: The URL received from the
'trendmicro-visionone-download-information-for-collected-forensic-file' will be valid for only
`60 seconds`

## Action: 'Start Analysis'

Submit file to sandbox for analysis.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                                                                                                                                                                                    | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| file_url          | URL pointing to the location of the file to be submitted.                                                                                                                                                                                          | Required     |
| file_name         | Name of the file to be analyzed.                                                                                                                                                                                                                   | Required     |
| document_pass     | The password for decrypting the submitted document. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding.                                                                                                  | Optional     |
| archive_pass      | The password for decrypting the submitted archive. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding.                                                                                                   | Optional     |
| arguments         | Parameter that allows you to specify Base64-encoded command line arguments to run the submitted file. The maximum argument length before encoding is 1024 bytes. Arguments are only available for Portable Executable (PE) files and script files. | Optional     |

Example input:

```
File Url
  https://someurl.com/file=somefile.bat
File Name
  some_file.bat
Document Password
  cGFzc3dvcmQK
Archive Password
  cGFzc3dvcmQK
Arguments
  IFMlYztbQA==
```

#### Context Output

| **Path**                           | **Type** | **Description**                                                |
| ---------------------------------- | -------- | -------------------------------------------------------------- |
| VisionOne.Start_Analysis.id        | String   | Unique alphanumeric string that identifies a submission        |
| VisionOne.Start_Analysis.digest    | String   | The hash value of the file                                     |
| VisionOne.Start_Analysis.arguments | String   | Command line arguments encoded in Base64 of the submitted file |

## Action: 'Status Check'

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                                    | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------- | ------------ |
| task_id           | Unique numeric string that identifies a response task.                                             | Required     |
| poll              | If script should wait until the task is finished before returning the result (disabled by default) | Optional     |
| poll_time_sec     | Maximum time to wait for the result to be available                                                | Optional     |

Example input:

```
Task ID
  00000012
Poll
  True
Poll Time Sec
  30
```

#### Context Output

| **Path**                                     | **Type** | **Description**                                                                                                  |
| -------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| VisionOne.Status_Check.id                    | String   | Unique numeric string that identifies a response task                                                            |
| VisionOne.Status_Check.status                | String   | The status of the command sent to the managing server. Possible task statuses: queued, running,succeeded, failed |
| VisionOne.Status_Check.created_date_time     | String   | Task completion time                                                                                             |
| VisionOne.Status_Check.last_action_date_time | String   | Timestamp in ISO 8601 format that indicates when the information about a submission was last updated             |
| VisionOne.Status_Check.action                | String   | Action applied to a submitted object                                                                             |
| VisionOne.Status_Check.description           | String   | Description of a response task                                                                                   |
| VisionOne.Status_Check.account               | String   | User that triggered the response                                                                                 |

## Action: 'Get Endpoint Info'

Gather information about an endpoint.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                        | **Required** |
| ----------------- | ---------------------------------------------------------------------- | ------------ |
| endpoint          | List of Hostname, macAddress, agentGuid or IP of the endpoint to query | Required     |
| query_op          | Logical operator to employ in the query. (AND/OR)                      | Required     |

Example input:

```
Endpoint
  127.127.127.127,endpoint2,endpoint4
Query Op
  or
```

#### Context Output

| **Path**                                            | **Type** | **Description**                                                                    |
| --------------------------------------------------- | -------- | ---------------------------------------------------------------------------------- |
| VisionOne.Get_Endpoint_Info.agent_guid              | String   | AgentGuid for the endpoint                                                         |
| VisionOne.Get_Endpoint_Info.login_account           | String   | Login Account for the endpoint                                                     |
| VisionOne.Get_Endpoint_Info.endpoint_name           | String   | Hostname of the endpoint                                                           |
| VisionOne.Get_Endpoint_Info.mac_address             | String   | MacAddress for the endpoint                                                        |
| VisionOne.Get_Endpoint_Info.ip                      | String   | IP address for the endpoint                                                        |
| VisionOne.Get_Endpoint_Info.os_name                 | String   | Operating system installed on an endpoint                                          |
| VisionOne.Get_Endpoint_Info.os_version              | String   | Version of the operating system installed on an endpoint                           |
| VisionOne.Get_Endpoint_Info.os_description          | String   | Description of the operating system installed on an endpoint                       |
| VisionOne.Get_Endpoint_Info.product_code            | String   | 3-character code that identifies Trend Micro products                              |
| VisionOne.Get_Endpoint_Info.installed_product_codes | String   | 3-character code that identifies the installed Trend Micro products on an endpoint |

## Action: 'Add Note'

Adds a note to an existing workbench alert.

Type: **generic**  
Read only: **False**

| **Argument Name** | **Description**                                 | **Required** |
| ----------------- | ----------------------------------------------- | ------------ |
| workbench id      | Workbench id of security incident in Vision One | Required     |
| content           | note to be added to the workbench event         | Required     |

Example input:

```
Alert ID
  WB-14-20190709-00003
Content 
  Suspected False Positive, please verify
```

#### Context Output

| **Path**                   | **Type** | **Description**                        |
| -------------------------- | -------- | -------------------------------------- |
| VisionOne.Add_Note.note_id | String   | ID of the newly created note.          |
| VisionOne.Add_Note.message | String   | Response message for the action taken. |

## Action: 'Update Status'

Updates the status of an existing workbench alert.

Type: **correct**  
Read only: **False**

| **Argument Name** | **Description**                                                                                                | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------- | ------------ |
| workbench_id      | The ID of the workbench alert that you would like to update the status for.                                    | Required     |
| status            | The status to assign to the workbench alert: new, in_progress, resolved_false_positive, resolved_true_positive | Required     |
| if_match          | The target resource will be updated only if it matches ETag of the target                                      | Required     |

Example input:

```
Workbench ID 
  WB-14-20190709-00003
If Match
  33a64df551425fcc55e4d42a148795d9f25f89d4
Status
  New
```

Note: `if_match` is the `etag` value provided by the get-alert-details action.

#### Context Output

| **Path**                        | **Type** | **Description** |
| ------------------------------- | -------- | --------------- |
| VisionOne.Update_Status.message | String   | Success or Fail |

## Action: 'Get Alert Details'

Displays information about the specified alert.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                  | **Required** |
| ----------------- | ---------------------------------------------------------------- | ------------ |
| workbench_id      | ID of the workbench alert you would like to get the details for. | Required     |

Example input:

```
Workbench ID
  WB-20837-20221111-0000
```

#### Context Output

| **Path**                          | **Type** | **Description**                                                     |
| --------------------------------- | -------- | ------------------------------------------------------------------- |
| VisionOne.Get_Alert_Details.alert | String   | Information associated to the workbenchID provided.                 |
| VisionOne.Get_Alert_Details.etag  | String   | An identifier for a specific version of a Workbench alert resource. |

## Action: 'Urls To Sandbox'

Submits URLs to the sandbox for analysis.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                                 | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------- | ------------ |
| urls              | Submits URLs to the sandbox for analysis. Note: You can submit a maximum of 10 URLs per request | Required     |

Example input:

```
URLS
  ["www.urlurl.com","www.zurlzurl.com", "https://testurl.com"]
```

#### Context Output

| **Path**                     | **Type** | **Description**                                              |
| ---------------------------- | -------- | ------------------------------------------------------------ |
| action_result.data.*.status  | Numeric  | HTTP status code for the action                              |
| action_result.data.*.task_id | String   | Unique alphanumeric string that identifies a submission      |
| action_result.data.*.url     | String   | The URL submitted to sandbox for analysis                    |
| action_result.data.*.id      | String   | Unique alphanumeric string that identifies a submission      |
| action_result.data.*.digest  | String   | md5, sha1 and sha256 values generated for the URL submission |

## Action: 'Enable Account'

Allows the user to sign in to new application and browser sessions.

Type: **correct**  
Read only: **False**

| **Argument Name**   | **Description**                                                             | **Required** |
| ------------------- | --------------------------------------------------------------------------- | ------------ |
| account_identifiers | Object containing `account_name` and optional `description` of action taken | Required     |

Example input:

```
Account Identifiers
  [{
    "account_name": "jdoe@testemailtest.com",
    "description": "Enable user account"
  }]
```

Note: `description` is optional and a default value is provided.

#### Context Output

| **Path**                         | **Type** | **Description**                                 |
| -------------------------------- | -------- | ----------------------------------------------- |
| VisionOne.Enable_Account.status  | Numeric  | HTTP status code for the action                 |
| VisionOne.Enable_Account.task_id | String   | Task ID generated after enabling a user account |

## Action: 'Disable Account'

Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session.

Type: **correct**  
Read only: **False**

| **Argument Name**   | **Description**                                                             | **Required** |
| ------------------- | --------------------------------------------------------------------------- | ------------ |
| account_identifiers | Object containing `account_name` and optional `description` of action taken | Required     |

Example input:

```
Account Identifiers
  [{
    "account_name": "jdoe@testemailtrain.com",
    "description": "Disable user account"},
  {
    "account_name": "jdoe1@testemailtrain.com"
  }]
```

Note: `description` is optional and a default value is provided.

#### Context Output

| **Path**                          | **Type** | **Description**                                  |
| --------------------------------- | -------- | ------------------------------------------------ |
| VisionOne.Disable_Account.status  | Numeric  | HTTP status code for the action                  |
| VisionOne.Disable_Account.task_id | String   | Task ID generated after disabling a user account |

## Action: 'Restore Email Message'

Restore quarantined email messages.

Type: **correct**  
Read only: **False**

| **Argument Name** | **Description**                                                                                                                    | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| email_identifiers | Object containing `mailbox` (Optional) and `message_id` and `description` or `description` and `unique_id` of the email to restore | Required     |

Example input:

```
Email Identifiers
Call with Message ID
  [{
    "description": "Restore email message",
    "mailbox": "jdoe@testemailtest.com",
    "message_id": "<AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0nNjgfLS2AABNpgTSQAA>"
  }]
Call with Unique ID
  [{
    "description": "Restore email message",
    "message_id": "DEapmEc2byACqAC-EWg0AAhCCNvg5sEua0n"
  }]
```

Note: `description` is optional and a default value is provided. When providing Unique ID, mailbox is not required. Additionally messages can only be restored if they have not been deleted.

#### Context Output

| **Path**                                | **Type** | **Description**                            |
| --------------------------------------- | -------- | ------------------------------------------ |
| VisionOne.Restore_Email_Message.status  | Numeric  | HTTP status code for the action            |
| VisionOne.Restore_Email_Message.task_id | String   | Task ID generated after restoring an email |

## Action: 'Sign Out Account'

Signs the user out of all active application and browser sessions.

Type: **contain**  
Read only: **False**

| **Argument Name**   | **Description**                                                                          | **Required** |
| ------------------- | ---------------------------------------------------------------------------------------- | ------------ |
| account_identifiers | Object containing `account_name` and `description` (Optional) of the account to sign-out | Required     |

Example input:

```
Account Identifiers
  [{
    "account_name": "jdoe@testemailtest.com",
    "description": "Sign out account"
  }]
```

Note: `description` is optional and a default value is provided.

#### Context Output

| **Path**                           | **Type** | **Description**                                  |
| ---------------------------------- | -------- | ------------------------------------------------ |
| VisionOne.Sign_Out_Account.status  | Numeric  | HTTP status code for the action                  |
| VisionOne.Sign_Out_Account.task_id | String   | Task ID generated after signing out user account |

## Action: 'Force Password Reset'

Signs the user out of all active application and browser sessions, and forces the user to create a new password during the next sign-in attempt.

Type: **contain**  
Read only: **False**

| **Argument Name**   | **Description**                                                                          | **Required** |
| ------------------- | ---------------------------------------------------------------------------------------- | ------------ |
| account_identifiers | Object containing `account_name` and `description` (Optional) of the account to sign-out | Required     |

Example input:

```
Account Identifiers
  [{
    "account_name": "jdoe@testemailtest.com",
    "description": "Force password reset"
  }]
```

Note: `description` is optional and a default value is provided.

#### Context Output

| **Path**                           | **Type** | **Description**                                  |
| ---------------------------------- | -------- | ------------------------------------------------ |
| VisionOne.Sign_Out_Account.status  | Numeric  | HTTP status code for the action.                 |
| VisionOne.Sign_Out_Account.task_id | String   | Task ID generated after forcing a password reset |

## Action: 'Sandbox Suspicious List'

Downloads the suspicious object list associated to the specified object.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                                    | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------- | ------------ |
| submit_id         | Unique alphanumeric string that identifies a submission.                                           | Required     |
| poll              | If script should wait until the task is finished before returning the result (disabled by default) | Optional     |
| poll_time_sec     | Maximum time to wait for the result to be available                                                | Optional     |

Example input:

```
Submit ID
  90406723-2b29-4e85-b0b2-ba58af8f63df
Poll
  false
Poll Time Sec
  0
```

#### Context Output

| **Path**                                  | **Type** | **Description**                                  |
| ----------------------------------------- | -------- | ------------------------------------------------ |
| VisionOne.Sandbox_Suspicious_List.status  | Numeric  | HTTP status code for the action                  |
| VisionOne.Sandbox_Suspicious_List.task_id | String   | Task ID generated after forcing a password reset |

## Action: 'Sandbox Analysis Result'

Displays the analysis results of the specified object.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                                    | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------- | ------------ |
| report_id         | Unique alphanumeric string that identifies a submission.                                           | Required     |
| poll              | If script should wait until the task is finished before returning the result (disabled by default) | Optional     |
| poll_time_sec     | Maximum time to wait for the result to be available                                                | Optional     |

Example input:

```
Report ID
  90406723-2b29-4e85-b0b2-ba58af8f63df
Poll
  False
Poll Time Sec
  0
```

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

## Action: 'Sandbox Investigation Package'

Downloads the Investigation Package of the specified object.

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description**                                                                                    | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------- | ------------ |
| submit_id         | Unique alphanumeric string that identifies a submission.                                           | Required     |
| poll              | If script should wait until the task is finished before returning the result (disabled by default) | Optional     |
| poll_time_sec     | Maximum time to wait for the result to be available                                                | Optional     |

Example input:

```
Submit ID
  00000012
Poll
  true
Poll Time Sec
  30
```

#### Context Output

| **Path**                                           | **Type** | **Description**                      |
| -------------------------------------------------- | -------- | ------------------------------------ |
| VisionOne.Sandbox_Investigation_Package.file_added | String   | Name of the .zip file added to Vault |

## Action: 'Get Suspicious List'

Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs in the Suspicious Object List and displays the information in a paginated list.

Type: **investigate**  
Read only: **True**

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| N/A               |                 |              |

#### Context Output

| **Path**                                         | **Type**             | **Description**            |
| ------------------------------------------------ | -------------------- | -------------------------- |
| VisionOne.Get_Suspicious_list.suspicious_objects | []suspicious_objects | List of Suspicious Objects |

## Action: 'Get Exception List'

Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs in the Exception List and displays it in a paginated list.

Type: **investigate**  
Read only: **True**

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| N/A               |                 |              |

#### Context Output

| **Path**                                       | **Type**            | **Description**           |
| ---------------------------------------------- | ------------------- | ------------------------- |
| VisionOne.Get_Exception_list.exception_objects | []exception_objects | List of Exception Objects |

This version of the Trend Micro app is compatible with Splunk SOAR version **5.1.0** and above.

## Authentication Information

The app uses HTTPS protocol for communicating with the Trend Micro Vision One server. For
authentication a Vision One API Token is used by the Splunk SOAR Connector.

----------------------------------------------------------------------------------------------------
