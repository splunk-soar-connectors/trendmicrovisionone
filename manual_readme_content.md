Trend Vision One for Splunk SOAR
======================================

Trend Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Vision One prevents the majority of attacks with automated protection

Splunk> Phantom
===============

Welcome to the open-source repository for Splunk> Phantom’s trendmicrovisionone App.

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) if you are interested in contributing, raising issues, or learning more about open-source Phantom apps.

Legal and License
-----------------

This Phantom App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.

#### Integration Author: Trend Micro

Support and maintenance for this integration are provided by the author. Please use the following contact details:

* **Email** : [integrations@trendmicro.com](mailto:integrations@trendmicro.com)

* * *

Port Information
----------------

The app uses HTTPS protocol for communicating with the VisionOne API server. Below are the default ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
| --- | --- | --- |
| https | tcp | 443 |

### Configuration Variables

The below configuration variables are required for this Connector to operate. These variables are specified when configuring a Trend Vision One asset in SOAR.

| VARIABLE | REQUIRED | TYPE | DESCRIPTION |
| --- | --- | --- | --- |
| **api_url** | required | string | The URL for your ETP instance |
| **api_key** | required | password | API key |

Configure Trend Vision One on Splunk SOAR
-----------------------------------------------

1.  Navigate to **Apps** \> **Unconfigured Apps** .
2.  Search for Trend Vision One.
3.  Click **CONFIGURE NEW ASSET** to create and configure a new integration instance.
4.  ALternatively click on **INSTALL APP** and drop a tarball of the app

  
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| **Asset name** | Unique name for this Trend Vision One instance runner asset | True |
| **Asset description** | Short description of the asset’s purpose | True |
| **Product vendor** | Trend Micro | True |
| **Product name** | Vision One | True |
| **Tags** | Optional tags to use in Playbooks | False |
| **API_URL** | Vision One API URL | True |
| **API_TOKEN** | Vision One API Token | True |
| **Polling interval (minutes)** | How often should security incident events be updated from Vision One | False |

1.  Click **TEST CONNECTIVITY** to validate the URLs, token, and connection.

### Supported Actions

[Test Connectivity](#action-test-connectivity) \- Validate the asset configuration for connectivity using supplied configuration  
[Get Endpoint Info](#action-get-endpoint-info) \- Gather information about an endpoint  
[Quarantine Device](#action-quarantine-device) \- Quarantine the endpoint  
[Unquarantine Device](#action-unquarantine-device) \- Unquarantine the endpoint  
[On Poll](#action-on-poll) \- Callback action for the on_poll ingest functionality  
[Status Check](#action-status-check) \- Checks the status of a task  
[Add To Blocklist](#action-add-to-blocklist) \- Adds an item to the Suspicious Objects list in Vision One  
[Remove From Blocklist](#action-remove-from-blocklist) \- Removes an item from the Suspicious Objects list  
[Quarantine Email Message](#action-quarantine-email-message) \- Quarantine the email message  
[Delete Email Message](#action-delete-email-message) \- Delete the email message  
[Terminate Process](#action-terminate-process) \- Terminate the process running on the endpoint  
[Add To Exception](#action-add-to-exception) \- Add object to exception list  
[Delete From Exception](#action-delete-from-exception) \- Delete object from exception list  
[Add To Suspicious](#action-add-to-suspicious) \- Add suspicious object to suspicious list  
[Delete From Suspicious](#action-delete-from-suspicious) \- Delete the suspicious object from suspicious list  
[Check Analysis Status](#action-check-analysis-status) \- Get the status of file analysis based on task id  
[Download Analysis Report](#action-download-analysis-report) \- Get the analysis report of a file based on report id  
[Collect Forensic File](#action-collect-forensic-file) \- Collect forensic file  
[Forensic File Info](#action-forensic-file-info) \- Get the download information for collected forensic file  
[Start Analysis](#action-start-analysis) \- Submit file to sandbox for analysis. For supported file types, check [here](https://docs.trendmicro.com/en-us/enterprise/trend-vision-one-olh/threat-intelligence-/sandbox-analysis/sandbox-supported-fi.aspx)  
[Add Note](#action-add-note) \- Adds a note to an existing workbench alert  
[Update Status](#action-update-status) \- Updates the status of an existing workbench alert  
[Get Alert Details](#action-get-alert-details) \- Displays information about the specified alert  
[Urls To Sandbox](#action-urls-to-sandbox) \- Submits URLs to the sandbox for analysis  
[Enable Account](#action-enable-account) \- Allows the user to sign in to new application and browser sessions  
[Disable Account](#action-disable-account) \- Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session  
[Restore Email Message](#action-restore-email-message) \- Restore quarantined email messages  
[Sign Out Account](#action-sign-out-account) \- Signs the user out of all active application and browser sessions  
[Force Password Reset](#action-force-password-reset) \- Signs the user out of all active application and browser sessions, and forces the user to create a new password during the next sign-in attempt  
[Sandbox Suspicious List](#action-sandbox-suspicious-list) \- Downloads the suspicious object list associated to the specified object  
[Sandbox Analysis Result](#action-sandbox-analysis-result) \- Displays the analysis results of the specified object  
[Sandbox Investigation Package](#action-sandbox-investigation-package) \- Downloads the Investigation Package of the specified object  
[Get Suspicious List](#action-get-suspicious-list) \- Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs in the Suspicious Object List and displays the information in a paginated list  
[Get Exception List](#action-get-exception-list) \- Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs in the Exception List and displays it in a paginated list

Commands
--------

You can execute these commands from the Splunk SOAR CLI, as part of an automation, or in a playbook.

Action: Test Connectivity
-------------------------

Validate the asset configuration for connectivity using supplied configuration variables.

Type: **test**  
Read only: **True**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| N/A |     |     |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| N/A |     |     |

Action: Add To Blocklist
------------------------

Add object(s) to blocklist.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Add to block list

**Suspicious Object Management**

* View, filter, and search
* Manage lists and configure settings

Type: **contain**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| block_objects | Object made up of `object_type`, `object_value` and `description` | Required |

Example input:

    Block Objects
        [{
          "object_type": "ip",
          "object_value": "6.6.6.6",
          "description": "Block IP"
        },{
          "object_type": "domain",
          "object_value": "hello.com",
        }]

Note: `description` is optional and a default value is automatically provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated for the action |

Note: To get the complete task status run polling command `status check` giving `taskId` as input parameter.

Action: Remove From Blocklist
-----------------------------

Remove object(s) from blocklist.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Add to block list

**Suspicious Object Management**

* View, filter, and search
* Manage lists and configure settings

Type: **correct**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| block_objects | Object made up of `object_type`, `object_value` and `description` | Required |

Example input:

    Block Objects
        [{
          "description": "Remove from blocklist",
          "object_type": "ip",
          "object_value": "6.6.6.3"
        }, {
          "object_type": "domain",
          "object_value": "hello.com",
        }]

Note: `description` is optional and a default value is automatically provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated for the action |

Note: To get the complete task status run polling command `status check` giving `taskId` as input parameter.

Action: Quarantine Email Message
--------------------------------

Quarantine email message(s).

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Quarantine/Restore messages

Type: **contain**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_identifiers | Object containing `message_id`, `mailbox` and `description` or `unique_id` and `description` | Required |

Example input:

    Email Identifiers
      Call using Message ID.
        [{
          "message_id": "<AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0nNjgfLS2AABNpgTSQAA>",
          "mailbox": "jdoe@testemailtest.com",
          "description": "Quarantine email message"
        }]
      Call using unique ID.
        [{
          "unique_id": "AAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0",
          "description": "Quarantine email message"
        }]

Note: `description` is optional and a default value is automatically provided. If `Unique ID` is being passed then the `mailbox ID` is not needed.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated for quarantining email message |

Note: To get the complete task status run polling command `status check` giving `taskId` as input parameter.

Action: Delete Email Message
----------------------------

Delete email message(s).

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Delete messages

Type: **correct**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_identifiers | Object containing `message_id`, `mailbox` and `description` or `unique_id` and `description` | Required |

Example input:

    Email Identifiers
      Call using message ID.
        [{
          "message_id": "<AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0nNjgfLS2AABNpgTSQAA>",
          "mailbox": "jdoe@testemailtest.com",
          "description": "Delete email message"
        }]
      Call using unique ID.
        [{
          "unique_id": "AAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0",
          "description": "Delete email message"
        }]

Note: `description` is optional and a default value is automatically provided. If `Unique ID` is being passed then the `mailbox ID` is not needed.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*status | Numeric | HTTP status code for the action |
| action\_result.data.*task\_id | String | Task ID generated for deleting email message |

Note: To get the complete task status run polling command `status check` giving `taskId` as input parameter.

Action: Quarantine Device
-------------------------

Quarantine endpoint(s).

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Isolate endpoint

Type: **contain**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_identifiers | Object containing of `endpoint` (hostname) and `description` or `agent_guid` and `description` | Required |

Example input:

    Endpoint Identifiers
        [{
          "endpoint": "endpoint123",
          "description": "quarantine device"
        }, {
          "agent_guid": "94632-7d79-451d-9ef8-2a2129e2",
          "description": "quarantine device"
        }]

Note: `endpoint` accepts agentGuid or hostname. `description` is optional and a default value is automatically provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*status | Numeric | HTTP status code for the action |
| action\_result.data.*task\_id | String | Task ID generated for quarantining endpoint |

Note: To get the complete task status run polling command `status check` giving `taskId` as input parameter. Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be `20 minutes` .

Action: Unquarantine Device
---------------------------

Restore endpoint(s) connectivity.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Isolate endpoint

Type: **correct**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_identifiers | Object containing of `endpoint` (hostname) and `description` or `agent_guid` and `description` | Required |

Example input:

    Endpoint Identifiers
        [{
          "endpoint": "endpoint123",
          "description": "Restore endpoint"
        }, {
          "agent_guid": "94632-7d79-451d-9ef8-2a2129e2",
          "description": "Restore endpoint"
        }]

Note: `endpoint` accepts either agent_guid or hostname. `description` is optional and a default value is automatically provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated for restoring endpoint |

Note: To get the complete task status run polling command `status check` giving `taskId` as input parameter. Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be `20 minutes` .

Action: On Poll
---------------

This polls information about workbench alerts that match the specified criteria in a paginated list.

**API key role permissions required: Workbench**

* View, filter, and search

Type: **ingest**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| starttime | Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the start of the data retrieval time range. The available oldest value is “1970-01-01T00:00:00Z” | False |
| endtime | Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the end of the data retrieval time range. Ensure that “endDateTime” is not earlier than “startDateTime” | False |

Example input:

    Start Time
        2020-01-01T10:00:00Z
      End Time
        2023-01-01T10:00:00Z

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.*.serialized\_alerts | \[\] List of SAE or TI Alerts | Array of alerts retrieved (awb-workbenchAlertV3) |

Action: Add To Exception
------------------------

Add object(s) to exception list.

**API key role permissions required: Suspicious Object Management**

* View, filter, and search
* Manage lists and configure settings

Type: **correct**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| block_objects | Object consisting of `object_type`, `object_value` and `description` | Required |

Example input:

    Block Objects
        [{"object_type": "ip","object_value": "1.2.6.9", "description": "Add to exception list"},
        {"object_type": "ip","object_value": "1.1.1.1"}]

Note: `description` is optional and a default value is automatically provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.multi\_response.*.status | Numeric | HTTP status code for the action |
| action\_result.data.multi\_response.*.task_id | N/A | Null |
| action\_result.data.multi\_response.*.total_count | Numeric | Total count of items in exception list |

Action: Delete From Exception
-----------------------------

Delete object(s) from exception list.

**API key role permissions required: Suspicious Object Management**

* View, filter, and search
* Manage lists and configure settings

Type: **correct**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| block_objects | Object consisting of `object_type`, `object_value` | Required |

Example input:

    Block Objects
        [{
          "object_type": "ip",
          "object_value": "1.6.6.3"
        }]

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.multi\_response.*.status | Numeric | HTTP status code for the action |
| action\_result.data.multi\_response.*.task_id | N/A | Null |
| action\_result.data.multi\_response.*.total_count | Numeric | Total count of objects in exception list |

Action: Add To Suspicious
-------------------------

Add object(s) to suspicious list.

**API key role permissions required: Suspicious Object Management**

* View, filter, and search
* Manage lists and configure settings

Type: **contain**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| block_objects | Object consisting of `object_type`, `object_value` and `scan_action`, `risk_level`, `expiry_days` and `description` | Required |

Example input:

    Block Objects
        [{
          "object_type": "ip",
          "risk_level": "high",
          "object_value": "6.6.6.3"
          "expiry_days": "30",
          "scan_action": "block",
          "description": "Add to suspicious list"
        }]

Note: `scan_action`, `risk_level`, `expiry_days` and `description` are optional and default values are provided for each.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.multi\_response.*.status | Numeric | HTTP status code for the action |
| action\_result.data.multi\_response.*.task_id | N/A | Null |
| action\_result.data.multi\_response.*.total_count | Numeric | Total count of objects in suspicious list |

Action: Delete From Suspicious
------------------------------

Delete object(s) from suspicious list.

**API key role permissions required: Suspicious Object Management**

* View, filter, and search
* Manage lists and configure settings

Type: **correct**  
Read only: **False**

#### Input

  
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| block_objects | Object consisting of `object_type` and `object_value` | Required |

Example input:

    Block Objects
        [{
          "object_type": "ip",
          "object_value": "6.6.6.4"
        }]

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.multi\_response.*.status | Numeric | HTTP status code for the action |
| action\_result.data.multi\_response.*.task_id | N/A | Null |
| action\_result.data.multi\_response.*.total_count | Numeric | Total count of objects in suspicious list |

Action: Terminate Process
-------------------------

Terminate process(es) running on endpoint(s).

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Terminate process

Type: **contain**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_identifiers | Object consisting of `endpoint` (hostname) or `agent_guid`, `file_sha1`, `filename` and `description` | Required |

Example input:

    Process Identifiers
        [{
          "endpoint": "endpoint123",
          "file_sha1": "984afc7.......95b519a081321"
          "description": "terminate process",
          "filename": "exmaplename.txt"
        }]

Note: `description` and `filename` are optional and a default value is provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated after terminating a process |

Note: To get the complete task status run polling command `status check` giving `taskId` as input parameter. Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout is `20 minutes` .

Action: Check Analysis Status
-----------------------------

Get the status of a sandbox submission based on task_id.

**API key role permissions required: Sandbox Analysis**

* View, filter, and search
* Submit objects

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Unique alphanumeric string that identifies the analysis results of a submission | Required |

Example input:

    Task ID
        8559a7ce-2b85-451b-8742-4b943ad76a22

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.id | String | Unique alphanumeric string that identifies a submission |
| action_result.data.*.status | String | Action applied to a submitted object. Possible values: succeeded, running, failed |
| action\_result.data.*.created\_date_time | String | Timestamp in ISO 8601 that indicates the object was submitted to the sandbox |
| action\_result.data.*.last\_action\_date\_time | String | Timestamp in ISO 8601 format that indicates when the information about a submission was last updated |
| action_result.data.*.action | String | Action applied to a submitted object |
| action\_result.data.*.resource\_location | String | Location of the submitted file |
| action\_result.data.*.is\_cached | String | Parameter that indicates if an object has been analyzed before by the Sandbox Analysis App. Submissions marked as cached do not count toward the daily reserve |
| action_result.data.*.digest | String | object (sandbox-digest) |
| action_result.data.*.arguments | String | Arguments for the file submitted |
| action_result.data.*.error | String | Error code and message for the submission |

Action: Download Analysis Report
--------------------------------

Get the analysis report of a file based on report id.

**API key role permissions required: Sandbox Analysis**

* View, filter, and search
* Submit objects

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submit_id | Unique alphanumeric string that identifies the analysis results of a submission | Required |
| poll | If script should wait until the task is finished before returning the result (enabled by default) | Optional |
| poll\_time\_sec | Maximum time to wait for the result to be available | Optional |

Example input:

    Submit ID
        8559a7ce-2b85-451b-8742-4b943ad76a22
      Poll
        true
      Poll Time Sec
        30

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.*.file\_added | String | Name of the PDF file added to Vault |

Action: Collect Forensic File
-----------------------------

Collect forensic file.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Collect file

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collect_files | Object containing `endpoint` (hostname) or `agent_guid`, `file_path` and `description` | Required |

Example input:

    Collect Files
        [{
          "endpoint": "endpoint123",
          "file_path": "C:/virus.exe",
          "description": "collect malicious file"
        }, {
          "agent_guid": "94632-7d79-451d-9ef8-2a2129e2",
          "file_path": "C:/some_file.exe"
        }]

Note: `description` is optional and a default value is provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated after collecting a file |

Note: To get the complete task status run polling command `status check` giving `taskId` as input parameter. Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be `20 minutes` .

Action: Forensic File Info
--------------------------

Get the download information for collected forensic file.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Download task result

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | task_id output from the collect forensic file command used to collect the file | Required |
| poll | If script should wait until the task is finished before returning the result (enabled by default) | Optional |
| poll\_time\_sec | Maximum time to wait for the result to be available | Optional |

Example input:

    Task ID
        00000012
      Poll
        True
      Poll Time Sec
        30

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.id | String | Unique numeric string that identifies a response task |
| action_result.data.*.status | String | The status of the command sent to the managing server. Possible task statuses: queued, running,succeeded, failed |
| action\_result.data.*.created\_date_time | String | Task completion time |
| action\_result.data.*.last\_action\_date\_time | String | Timestamp in ISO 8601 format that indicates when the information about a submission was last updated |
| action_result.data.*.action | String | Action applied to a submitted object |
| action_result.data.*.description | String | Description of a response task |
| action_result.data.*.account | String | User that triggered the response |
| action\_result.data.*.agent\_guid | String | Unique alphanumeric string that identifies an installed agent |
| action\_result.data.*.endpoint\_name | String | Endpoint name of the target endpoint |
| action\_result.data.*.file\_path | String | File path of the file to be collected from the target |
| action\_result.data.*.file\_sha1 | String | string (arp-sha1) |
| action\_result.data.*.file\_sha256 | String | string (arp-sha256) |
| action\_result.data.*.file\_size | String | Size of the collected file in bytes |
| action\_result.data.*.resource\_location | String | URL to download the collected file |
| action\_result.data.*.expired\_date_time | String | Timestamp in ISO 8601 format |
| action_result.data.*.password | String | Password to get the resource |
| action_result.data.*.error | String | Object that contains information about the unsuccessful task. response |

Note: The URL received from the ‘trendmicro-visionone-download-information-for-collected-forensic-file’ will be valid for only `60 seconds`

Action: Start Analysis
----------------------

Submit file to sandbox for analysis.

**API key role permissions required: Sandbox Analysis**

* View, filter, and search
* Submit objects

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_url | URL pointing to the location of the file to be submitted | Required |
| file_name | Name of the file to be analyzed | Required |
| document_pass | The password for decrypting the submitted document. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding | Optional |
| archive_pass | The password for decrypting the submitted archive. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding | Optional |
| arguments | Parameter that allows you to specify Base64-encoded command line arguments to run the submitted file. The maximum argument length before encoding is 1024 bytes. Arguments are only available for Portable Executable (PE) files and script files | Optional |

Example input:

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

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.id | String | Unique alphanumeric string that identifies a submission |
| action_result.data.*.digest | String | object (sandbox-digest) |
| action_result.data.*.arguments | String | Command line arguments encoded in Base64 of the submitted file |

Action: Status Check
--------------------

Check the status of a task.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Download task result

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Unique numeric string that identifies a response task | Required |
| poll | If script should wait until the task is finished before returning the result (enabled by default) | Optional |
| poll\_time\_sec | Maximum time to wait for the result to be available | Optional |

Example input:

    Task ID
        00000012
      Poll
        True
      Poll Time Sec
        30

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*..id | String | Unique numeric string that identifies a response task |
| action_result.data.*..status | String | The status of the command sent to the managing server. Possible task statuses: queued, running,succeeded, failed |
| action\_result.data.*..created\_date_time | String | Task completion time |
| action\_result.data.*..last\_action\_date\_time | String | Timestamp in ISO 8601 format that indicates when the information about a submission was last updated |
| action_result.data.*..action | String | Action applied to a submitted object |
| action_result.data.*..description | String | Description of a response task |
| action_result.data.*..account | String | User that triggered the response |

Action: Get Endpoint Info
-------------------------

Gather information about an endpoint.

**API key role permissions required: Endpoint Inventory**

* View

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | List of `hostname`, `macAddress`, `agentGuid` or `IP` of the endpoint to query | Required |
| query_op | Logical operator to employ in the query. (AND/OR) | Required |

Example input:

    Endpoint
        127.127.127.127,endpoint2,endpoint4
      Query Op
        or

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.*.agent\_guid | String | AgentGuid for the endpoint |
| action\_result.data.*.login\_account | String | Login Account for the endpoint |
| action\_result.data.*.endpoint\_name | String | Hostname of the endpoint |
| action\_result.data.*.mac\_address | String | MacAddress for the endpoint |
| action_result.data.*.ip | String | IP address for the endpoint |
| action\_result.data.*.os\_name | String | Operating system installed on an endpoint |
| action\_result.data.*.os\_version | String | Version of the operating system installed on an endpoint |
| action\_result.data.*.os\_description | String | Description of the operating system installed on an endpoint |
| action\_result.data.*.product\_code | String | 3-character code that identifies Trend Micro products |
| action\_result.data.*.installed\_product_codes | String | 3-character code that identifies the installed Trend Micro products on an endpoint |

Action: Add Note
----------------

Adds a note to an existing workbench alert.

**API key role permissions required: Workbench**

* Modify alert details

Type: **generic**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workbench_id | Workbench id of security incident in Vision One | Required |
| content | note to be added to the workbench event | Required |

Example input:

    Alert ID
        WB-14-20190709-00003
      Content
        Suspected False Positive, please verify

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.*.note\_id | String | ID of the newly created note |
| action_result.data.*.message | String | Response message for the action taken |

Action: Update Status
---------------------

Updates the status of an existing workbench alert.

**API key role permissions required: Workbench**

* Modify alert details

Type: **correct**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workbench_id | The ID of the workbench alert that you would like to update the status for | Required |
| status | The status to assign to the workbench alert: `new`, `in_progress`, `true_positive`, `false_positive`, `benign_true_positive`, `closed` | Required |
| if_match | The target resource will be updated only if it matches `ETag` of the target | Required |

Example input:

    Workbench ID
        WB-14-20190709-00003
      If Match
        33a64df551425fcc55e4d42a148795d9f25f89d4
      Status
        New

Note: `if_match` is the `etag` value provided by the get-alert-details action.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.message | String | Message notifying of success or failure |

Action: Get Alert Details
-------------------------

Displays information about a specified alert.

**API key role permissions required: Workbench**

* View, filter, and search

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workbench_id | ID of the workbench alert you would like to get the details for | Required |

Example input:

    Workbench ID
        WB-20837-20221111-0000

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.alert | String | Information associated to the workbenchID provided |
| action_result.data.*.etag | String | An identifier for a specific version of a Workbench alert resource |

Action: Urls To Sandbox
-----------------------

Submits URLs to the sandbox for analysis.

**API key role permissions required: Sandbox Analysis**

* View, filter, and search
* Submit objects

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | List of URLs to be sent to sandbox for analysis. Note: You can submit a maximum of 10 URLs per request | Required |

Example input:

    URLS
        ["www.urlurl.com","www.zurlzurl.com", "https://testurl.com"]

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Unique alphanumeric string that identifies a submission |
| action_result.data.*.url | String | The URL submitted to sandbox for analysis |
| action_result.data.*.id | String | Unique alphanumeric string that identifies a submission |
| action_result.data.*.digest | String | object (sandbox-digest) |

Action: Enable Account
----------------------

Allow the user(s) to sign in to new application and browser sessions.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Enable/Disable user account, force sign out, force password reset

Type: **correct**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_identifiers | Object containing `account_name` and `description` | Required |

Example input:

    Account Identifiers
        [{
          "account_name": "jdoe@testemailtest.com",
          "description": "Enable user account"
        }]

Note: `description` is optional and a default value is provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated after enabling a user account |

Action: Disable Account
-----------------------

Sign out user(s) of all active application and browser sessions, and prevent the user(s) from signing in any new session.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Enable/Disable user account, force sign out, force password reset

Type: **correct**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_identifiers | Object containing `account_name` and `description` | Required |

Example input:

    Account Identifiers
        [{
          "account_name": "jdoe@testemailtrain.com",
          "description": "Disable user account"},
        {
          "account_name": "jdoe1@testemailtrain.com"
        }]

Note: `description` is optional and a default value is provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated after disabling a user account |

Action: Restore Email Message
-----------------------------

Restore quarantined email message(s).

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Quarantine/Restore messages

Type: **correct**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_identifiers | Object containing `message_id`, `mailbox` and `description` or `unique_id` and `description` | Required |

Example input:

    Email Identifiers
      Call with Message ID
        [{
          "message_id": "<AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0AAhCCNvg5sEua0nNjgfLS2AABNpgTSQAA>",
          "mailbox": "jdoe@testemailtest.com",
          "description": "Restore email message"
        }]
      Call with Unique ID
        [{
          "unique_id": "DEapmEc2byACqAC-EWg0AAhCCNvg5sEua0n",
          "description": "Restore email message"
        }]

Note: `description` is optional and a default value is provided. When providing Unique ID, mailbox is not required. Additionally messages can only be restored if they have not been deleted.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated after restoring an email |

Action: Sign Out Account
------------------------

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Enable/Disable user account, force sign out, force password reset

Sign out user(s) out of all active application and browser sessions.

Type: **contain**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_identifiers | Object containing `account_name` and `description` | Required |

Example input:

    Account Identifiers
        [{
          "account_name": "jdoe@testemailtest.com",
          "description": "Sign out account"
        }]

Note: `description` is optional and a default value is provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action |
| action\_result.data.*.task\_id | String | Task ID generated after signing out user account |

Action: Force Password Reset
----------------------------

Signs the user out of all active application and browser sessions, and forces the user to create a new password during the next sign-in attempt.

**API key role permissions required: Response Management**

* View, filter, and search (Task List tab)
* Enable/Disable user account, force sign out, force password reset

Type: **contain**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_identifiers | Object containing `account_name` and `description` | Required |

Example input:

    Account Identifiers
        [{
          "account_name": "jdoe@testemailtest.com",
          "description": "Force password reset"
        }]

Note: `description` is optional and a default value is provided.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.status | Numeric | HTTP status code for the action. |
| action\_result.data.*.task\_id | String | Task ID generated after forcing a password reset |

Action: Sandbox Suspicious List
-------------------------------

Downloads the suspicious object list associated to the specified object.

**API key role permissions required: Sandbox Analysis**

* View, filter, and search
* Submit objects

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submit_id | Unique alphanumeric string that identifies a submission. | Required |
| poll | If script should wait until the task is finished before returning the result (enabled by default) | Optional |
| poll\_time\_sec | Maximum time to wait for the result to be available | Optional |

Example input:

    Submit ID
        90406723-2b29-4e85-b0b2-ba58af8f63df
      Poll
        false
      Poll Time Sec
        0

Note: Suspicious Object Lists are only available for objects with a high risk level.

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.*.risk\_level | String | Risk Level of suspicious object |
| action\_result.data.*.analysis\_completion\_date\_time | String | Analyze time of suspicious object |
| action\_result.data.*.expired\_date_time | String | Expire time of suspicious object |
| action\_result.data.*.root\_sha1 | String | Sample sha1 generate this suspicious object |
| action_result.data.*.type | String | Type of item submitted to sandbox for analysis |
| action_result.data.*.value | String | Value of item submitted to sandbox for analysis |

Action: Sandbox Analysis Result
-------------------------------

Displays the analysis results of the specified object.

**API key role permissions required: Sandbox Analysis**

* View, filter, and search
* Submit objects

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Unique alphanumeric string that identifies a submission | Required |
| poll | If script should wait until the task is finished before returning the result (enabled by default) | Optional |
| poll\_time\_sec | Maximum time to wait for the result to be available | Optional |

Example input:

    Report ID
        90406723-2b29-4e85-b0b2-ba58af8f63df
      Poll
        False
      Poll Time Sec
        0

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.id | String | Unique alphanumeric string that identifies the analysis results of a submitted object |
| action_result.data.*.type | String | Object type |
| action_result.data.*.digest | String | object (sandbox-digest) |
| action\_result.data.*.risk\_level | String | The risk level assigned to the object by the sandbox |
| action\_result.data.*.analysis\_completion\_date\_time | String | Timestamp in ISO 8601 format that indicates when the analysis was completed |
| action_result.data.*.arguments | String | Command line arguments encoded in Base64 of the submitted file |
| action\_result.data.*.detection\_names | String | The name of the threat as detected by the sandbox |
| action\_result.data.*.threat\_types | String | The threat type as detected by the sandbox |
| action\_result.data.*.true\_file_type | String | File Type of the Object |

Action: Sandbox Investigation Package
-------------------------------------

Downloads the Investigation Package of the specified object.

**API key role permissions required: Sandbox Analysis**

* View, filter, and search
* Submit objects

Type: **investigate**  
Read only: **False**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submit_id | Unique alphanumeric string that identifies a submission | Required |
| poll | If script should wait until the task is finished before returning the result (enabled by default) | Optional |
| poll\_time\_sec | Maximum time to wait for the result to be available | Optional |

Example input:

    Submit ID
        00000012
      Poll
        true
      Poll Time Sec
        30

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action\_result.data.*.file\_added | String | Name of the .zip file added to Vault |

Action: Get Suspicious List
---------------------------

Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, email addresses, or URLs in the Suspicious Object List and displays the information in a paginated list.

**API key role permissions required: Suspicious Object Management**

* View, filter, and search

Type: **investigate**  
Read only: **True**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| N/A |     |     |

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.value | String | Value that was submitted to suspicious list |
| action_result.data.*.type | String | Type of object that was added to suspicious list |
| action\_result.data.*.last\_modified\_date\_time | String | Timestamp in ISO 8601 format that indicates the last time the information about a suspicious object was modified |
| action_result.data.*.description | String | Description of an object |
| action\_result.data.*.scan\_action | String | Action that connected products apply after detecting a suspicious object |
| action\_result.data.*.risk\_level | String | Risk level of a suspicious object |
| action\_result.data.*.in\_exception_list | String | Value that indicates if a suspicious object is in the exception list |
| action\_result.data.*.expired\_date_time | String | Timestamp in ISO 8601 format that indicates when the suspicious object expires |

Action: Get Exception List
--------------------------

Retrieves information about domains, file SHA-1, file SHA-256, IP addresses, sender addresses, or URLs in the Exception List and displays it in a paginated list.

**API key role permissions required: Suspicious Object Management**

* View, filter, and search

Type: **investigate**  
Read only: **True**

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| N/A |     |     |

#### Context Output

  
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| action_result.data.*.value | String | Value that was submitted to exception list |
| action_result.data.*.type | String | Type of object that was added to exception list |
| action\_result.data.*.last\_modified\_date\_time | String | The time the object was created |
| action_result.data.*.description | String | Description of an object |

This version of the Trend Micro app is compatible with Splunk SOAR version **5.1.0** and above.

Authentication Information
--------------------------

The app uses HTTPS protocol for communicating with the Trend Vision One server. For authentication a Vision One API Token is used by the Splunk SOAR Connector.

* * *