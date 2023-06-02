# File: trendmicrovisionone_consts.py

# Copyright (c) Trend Micro, 2022-2023

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
API_VER = "v3.0"

# COMMAND NAMES
ENABLE_USER_ACCOUNT_COMMAND = "trendmicro-visionone-enable-user-account"
DISABLE_USER_ACCOUNT_COMMAND = "trendmicro-visionone-disable-user-account"
FORCE_SIGN_OUT_COMMAND = "trendmicro-visionone-force-sign-out"
FORCE_PASSWORD_RESET_COMMAND = "trendmicro-visionone-force-password-reset"
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
GET_SANDBOX_SUBMISSION_STATUS_COMMAND = (
    "trendmicro-visionone-get-sandbox-submission-status"
)
GET_SANDBOX_ANALYSIS_RESULTS_COMMAND = (
    "trendmicro-visionone-get-sandbox-analysis-results"
)
DOWNLOAD_SANDBOX_ANALYSIS_REPORT_COMMAND = (
    "trendmicro-visionone-download-sandbox-analysis-report"
)
DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND = (
    "trendmicro-visionone-download-investigation-package"
)
DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND = (
    "trendmicro-visionone-download-suspicious-object-list"
)
TEST_CONNECTIVITY_COMMAND = "trendmicro-visionone-test-connectivity"
COLLECT_FILE_COMMAND = "trendmicro-visionone-collect-forensic-file"
FILE_TO_SANDBOX_COMMAND = "trendmicro-visionone-submit-file-to-sandbox"
CHECK_TASK_STATUS_COMMAND = "trendmicro-visionone-check-task-status"
FETCH_INCIDENTS_COMMAND = "fetch-incidents"
UPDATE_STATUS_COMMAND = "trendmicro-visionone-update-status"
ADD_NOTE_COMMAND = "trendmicro-visionone-add-note"
