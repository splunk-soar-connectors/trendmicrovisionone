API_VER = "v2.0"
# End Points
ADD_BLOCKLIST_ENDPOINT = "/%s/xdr/response/block" % API_VER
REMOVE_BLOCKLIST_ENDPOINT = "/%s/xdr/response/restoreBlock" % API_VER
QUARANTINE_EMAIL_ENDPOINT = "/%s/xdr/response/quarantineMessage" % API_VER
DELETE_EMAIL_ENDPOINT = "/%s/xdr/response/deleteMessage" % API_VER
ISOLATE_CONNECTION_ENDPOINT = "/%s/xdr/response/isolate" % API_VER
TERMINATE_PROCESS_ENDPOINT = "/%s/xdr/response/terminateProcess" % API_VER
RESTORE_CONNECTION_ENDPOINT = "/%s/xdr/response/restoreIsolate" % API_VER
ADD_OBJECT_TO_EXCEPTION_LIST = (
    "/%s/xdr/threatintel/suspiciousObjects/exceptions" % API_VER
)
DELETE_OBJECT_FROM_EXCEPTION_LIST = (
    "/%s/xdr/threatintel/suspiciousObjects/exceptions/delete" % API_VER
)
ADD_OBJECT_TO_SUSPICIOUS_LIST = "/%s/xdr/threatintel/suspiciousObjects" % API_VER
DELETE_OBJECT_FROM_SUSPICIOUS_LIST = (
    "/%s/xdr/threatintel/suspiciousObjects/delete" % API_VER
)
TASK_DETAIL_ENDPOINT = "/%s/xdr/response/getTask" % API_VER
GET_COMPUTER_ID_ENDPOINT = "/%s/xdr/eiqs/query/agentInfo" % API_VER
GET_ENDPOINT_INFO_ENDPOINT = "/%s/xdr/eiqs/query/endpointInfo" % API_VER
GET_FILE_STATUS = "/%s/xdr/sandbox/tasks/{taskId}" % API_VER
GET_FILE_REPORT = "/%s/xdr/sandbox/reports/{reportId}" % API_VER
COLLECT_FORENSIC_FILE = "/%s/xdr/response/collectFile" % API_VER
DOWNLOAD_INFORMATION_COLLECTED_FILE = "/%s/xdr/response/downloadInfo" % API_VER
SUBMIT_FILE_TO_SANDBOX = "/%s/xdr/sandbox/file" % API_VER
WORKBENCH_HISTORIES = "/%s/xdr/workbench/workbenchHistories" % API_VER
ADD_NOTE_ENDPOINT = "/%s/xdr/workbench/workbenches/{workbenchId}/notes" % API_VER
UPDATE_STATUS_ENDPOINT = "/%s/xdr/workbench/workbenches/{workbenchId}" % API_VER
# COMMAND NAMES
ADD_BLOCKLIST_COMMAND = "trendmicro-visionone-add-to-block-list"
REMOVE_BLOCKLIST_COMMAND = "trendmicro-visionone-remove-from-block-list"
QUARANTINE_EMAIL_COMMAND = "trendmicro-visionone-quarantine-email-message"
DELETE_EMAIL_COMMAND = "trendmicro-visionone-delete-email-message"
ISOLATE_ENDPOINT_COMMAND = "trendmicro-visionone-isolate-endpoint"
RESTORE_ENDPOINT_COMMAND = "trendmicro-visionone-restore-endpoint-connection"
TERMINATE_PROCESS_COMMAND = "trendmicro-visionone-terminate-process"
ADD_EXCEPTION_LIST_COMMAND = "trendmicro-visionone-add-objects-to-exception-list"
DELETE_EXCEPTION_LIST_COMMAND = (
    "trendmicro-visionone-delete-objects-from-exception-list"
)
ADD_SUSPICIOUS_LIST_COMMAND = "trendmicro-visionone-add-objects-to-suspicious-list"
DELETE_SUSPICIOUS_LIST_COMMAND = (
    "trendmicro-visionone-delete-objects-from-suspicious-list"
)
GET_FILE_ANALYSIS_STATUS = "trendmicro-visionone-get-file-analysis-status"
GET_FILE_ANALYSIS_REPORT = "trendmicro-visionone-get-file-analysis-report"
COLLECT_FILE = "trendmicro-visionone-collect-forensic-file"
DOWNLOAD_COLLECTED_FILE = (
    "trendmicro-visionone-download-information-for-collected-forensic-file"
)
FILE_TO_SANDBOX = "trendmicro-visionone-submit-file-to-sandbox"
CHECK_TASK_STATUS = "trendmicro-visionone-check-task-status"
FETCH_INCIDENTS = "fetch-incidents"
UPDATE_STATUS = "trendmicro-visionone-update-status"
ADD_NOTE = "trendmicro-visionone-add-note"
