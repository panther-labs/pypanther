import json
from datetime import timedelta

from panther_detection_helpers.caching import put_string_set

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_oss_helpers import resolve_timestamp_string

standard_new_aws_account_created_tests: list[RuleTest] = [
    RuleTest(
        name="AWS Account created",
        expected_result=True,
        mocks=[RuleMock(object_name="put_string_set", return_value="")],
        log={
            "awsRegion": "us-east-1",
            "eventID": "axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "eventName": "CreateAccountResult",
            "eventSource": "organizations.amazonaws.com",
            "eventTime": "2021-05-20 15:53:47Z",
            "eventType": "AwsServiceEvent",
            "eventVersion": "1.08",
            "managementEvent": True,
            "p_log_type": "AWS.CloudTrail",
            "p_any_aws_account_ids": ["111111111111", "222222222222"],
            "p_event_time": "2021-05-20 15:53:47Z",
            "readOnly": False,
            "recipientAccountId": "292442345278",
            "serviceEventDetails": '{\n  "createAccountStatus": {\n    "accountId": "1111111111111111",\n    "accountName": "****",\n    "completedTimestamp": "May 20, 2021 3:53:47 PM",\n    "id": "car-aaaaaaaaaaaaaaaaaaaaaaaaaaa",\n    "requestedTimestamp": "May 20, 2021 3:53:44 PM",\n    "state": "SUCCEEDED"\n  }\n}',
        },
    ),
    RuleTest(
        name="Non-Account-Creation Event",
        expected_result=False,
        mocks=[RuleMock(object_name="put_string_set", return_value="")],
        log={
            "awsRegion": "us-east-1",
            "eventName": "CreateAccount",
            "eventTime": "2020-11-05 21:21:46Z",
            "eventType": "AwsApiCall",
            "eventVersion": "1.05",
            "recipientAccountId": "111111111111111111111111111",
            "requestID": "2222222222222222222222222222",
            "requestParameters": '{\n  "accountName": "****",\n  "email": "****",\n  "roleName": "SomeRole"\n}',
            "responseElements": '{\n  "createAccountStatus": {\n    "accountName": "****",\n    "id": "car-3333333333",\n    "requestedTimestamp": "Nov 5, 2020 9:21:45 PM",\n    "state": "IN_PROGRESS"\n  }\n}',
            "sourceIPAddress": "72.177.120.134",
            "p_event_time": "2020-11-05 21:21:46Z",
            "p_log_type": "AWS.CloudTrail",
            "p_any_aws_account_ids": ["222222222222"],
        },
    ),
]


@panther_managed
class StandardNewAWSAccountCreated(Rule):
    id = "Standard.NewAWSAccountCreated-prototype"
    display_name = "New AWS Account Created"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["DataModel", "Indicator Collection", "Persistence:Create Account"]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    default_description = "A new AWS account was created"
    default_runbook = (
        "A new AWS account was created, ensure it was created through standard practice and is for a valid purpose."
    )
    default_reference = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security_incident-response.html#:~:text=AWS%20Organizations%20information%20in%20CloudTrail"
    summary_attributes = ["p_any_aws_account_ids"]
    tests = standard_new_aws_account_created_tests
    # Days an account is considered new
    TTL = timedelta(days=3)

    def parse_new_account_id(self, event):
        if event.get("serviceEventDetails"):
            try:
                details = json.loads(event.get("serviceEventDetails"))
                return str(details.get("createAccountStatus", {}).get("accountId", "<UNKNOWN_ACCOUNT_ID>"))
            except (TypeError, ValueError):
                return "<UNABLE TO PARSE ACCOUNT ID>"
        return "<UNKNOWN ACCOUNT ID>"

    def rule(self, event):
        if event.udm("event_type") != event_type.ACCOUNT_CREATED:
            return False
        account_id = self.parse_new_account_id(event)
        event_time = resolve_timestamp_string(event.get("p_event_time"))
        expiry_time = event_time + self.TTL
        account_event_id = f"new_aws_account_{event.get('p_row_id')}"
        if account_id:
            put_string_set("new_account - " + account_id, [account_event_id], expiry_time.strftime("%s"))
        return True

    def title(self, event):
        return f"A new AWS account has been created. Account ID - [{self.parse_new_account_id(event)}]"
