from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import aws_rule_context

awsiam_group_read_only_events_tests: list[RuleTest] = [
    RuleTest(
        name="Get Group",
        expected_result=True,
        log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventID": "883efb94-aa58-4512-beb7-10a5fffa33e4",
            "eventName": "GetGroup",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2022-12-11 19:42:55",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": True,
            "recipientAccountId": "1231231234",
            "requestID": "f92dd1a7-ad07-4fef-9511-1081d2dd3585",
            "requestParameters": {"maxItems": 1000, "userName": "user-name"},
            "sourceIPAddress": "cloudformation.amazonaws.com",
            "userAgent": "cloudformation.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "ASIAVKVYIOO7BDL4T5NG",
                "accountId": "1231231234",
                "arn": "arn:aws:sts::1231231234:assumed-role/AssumedRole-us-east-2/123123123456",
                "invokedBy": "cloudformation.amazonaws.com",
                "principalId": "AROAVKVYIOO7JN7TN7NSA:123123123456",
                "sessionContext": {
                    "attributes": {"creationDate": "2022-12-11T19:42:54Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "1231231234",
                        "arn": "arn:aws:iam::1231231234:role/PAssumedRole-us-east-2",
                        "principalId": "AROAVKVYIOO7JN7TN7NSA",
                        "type": "Role",
                        "userName": "AssumedRole-us-east-2",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
    RuleTest(
        name="Get Group Policy",
        expected_result=True,
        log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventID": "883efb94-aa58-4512-beb7-10a5fffa33e4",
            "eventName": "GetGroupPolicy",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2022-12-11 19:42:55",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": True,
            "recipientAccountId": "1231231234",
            "requestID": "f92dd1a7-ad07-4fef-9511-1081d2dd3585",
            "requestParameters": {"maxItems": 1000, "userName": "user-name"},
            "sourceIPAddress": "cloudformation.amazonaws.com",
            "userAgent": "cloudformation.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "ASIAVKVYIOO7BDL4T5NG",
                "accountId": "1231231234",
                "arn": "arn:aws:sts::1231231234:assumed-role/AssumedRole-us-east-2/123123123456",
                "invokedBy": "cloudformation.amazonaws.com",
                "principalId": "AROAVKVYIOO7JN7TN7NSA:123123123456",
                "sessionContext": {
                    "attributes": {"creationDate": "2022-12-11T19:42:54Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "1231231234",
                        "arn": "arn:aws:iam::1231231234:role/PAssumedRole-us-east-2",
                        "principalId": "AROAVKVYIOO7JN7TN7NSA",
                        "type": "Role",
                        "userName": "AssumedRole-us-east-2",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
    RuleTest(
        name="List Attached Group Policies",
        expected_result=True,
        log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventID": "883efb94-aa58-4512-beb7-10a5fffa33e4",
            "eventName": "ListAttachedGroupPolicies",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2022-12-11 19:42:55",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": True,
            "recipientAccountId": "1231231234",
            "requestID": "f92dd1a7-ad07-4fef-9511-1081d2dd3585",
            "requestParameters": {"maxItems": 1000, "userName": "user-name"},
            "sourceIPAddress": "cloudformation.amazonaws.com",
            "userAgent": "cloudformation.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "ASIAVKVYIOO7BDL4T5NG",
                "accountId": "1231231234",
                "arn": "arn:aws:sts::1231231234:assumed-role/AssumedRole-us-east-2/123123123456",
                "invokedBy": "cloudformation.amazonaws.com",
                "principalId": "AROAVKVYIOO7JN7TN7NSA:123123123456",
                "sessionContext": {
                    "attributes": {"creationDate": "2022-12-11T19:42:54Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "1231231234",
                        "arn": "arn:aws:iam::1231231234:role/PAssumedRole-us-east-2",
                        "principalId": "AROAVKVYIOO7JN7TN7NSA",
                        "type": "Role",
                        "userName": "AssumedRole-us-east-2",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
    RuleTest(
        name="List Groups",
        expected_result=True,
        log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventID": "883efb94-aa58-4512-beb7-10a5fffa33e4",
            "eventName": "ListGroups",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2022-12-11 19:42:55",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": True,
            "recipientAccountId": "1231231234",
            "requestID": "f92dd1a7-ad07-4fef-9511-1081d2dd3585",
            "requestParameters": {"maxItems": 1000, "userName": "user-name"},
            "sourceIPAddress": "cloudformation.amazonaws.com",
            "userAgent": "cloudformation.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "ASIAVKVYIOO7BDL4T5NG",
                "accountId": "1231231234",
                "arn": "arn:aws:sts::1231231234:assumed-role/AssumedRole-us-east-2/123123123456",
                "invokedBy": "cloudformation.amazonaws.com",
                "principalId": "AROAVKVYIOO7JN7TN7NSA:123123123456",
                "sessionContext": {
                    "attributes": {"creationDate": "2022-12-11T19:42:54Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "1231231234",
                        "arn": "arn:aws:iam::1231231234:role/PAssumedRole-us-east-2",
                        "principalId": "AROAVKVYIOO7JN7TN7NSA",
                        "type": "Role",
                        "userName": "AssumedRole-us-east-2",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
    RuleTest(
        name="List Groups for User",
        expected_result=True,
        log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventID": "883efb94-aa58-4512-beb7-10a5fffa33e4",
            "eventName": "ListGroupsForUser",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2022-12-11 19:42:55",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": True,
            "recipientAccountId": "1231231234",
            "requestID": "f92dd1a7-ad07-4fef-9511-1081d2dd3585",
            "requestParameters": {"maxItems": 1000, "userName": "user-name"},
            "sourceIPAddress": "cloudformation.amazonaws.com",
            "userAgent": "cloudformation.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "ASIAVKVYIOO7BDL4T5NG",
                "accountId": "1231231234",
                "arn": "arn:aws:sts::1231231234:assumed-role/AssumedRole-us-east-2/123123123456",
                "invokedBy": "cloudformation.amazonaws.com",
                "principalId": "AROAVKVYIOO7JN7TN7NSA:123123123456",
                "sessionContext": {
                    "attributes": {"creationDate": "2022-12-11T19:42:54Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "1231231234",
                        "arn": "arn:aws:iam::1231231234:role/PAssumedRole-us-east-2",
                        "principalId": "AROAVKVYIOO7JN7TN7NSA",
                        "type": "Role",
                        "userName": "AssumedRole-us-east-2",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
    RuleTest(
        name="Detach User Group",
        expected_result=False,
        log={
            "awsRegion": "us-east-1",
            "eventCategory": "Management",
            "eventID": "883efb94-aa58-4512-beb7-10a5fffa33e4",
            "eventName": "DetachUserGroup",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2022-12-11 19:42:55",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": True,
            "recipientAccountId": "1231231234",
            "requestID": "f92dd1a7-ad07-4fef-9511-1081d2dd3585",
            "requestParameters": {"maxItems": 1000, "userName": "user-name"},
            "sourceIPAddress": "cloudformation.amazonaws.com",
            "userAgent": "cloudformation.amazonaws.com",
            "userIdentity": {
                "accessKeyId": "ASIAVKVYIOO7BDL4T5NG",
                "accountId": "1231231234",
                "arn": "arn:aws:sts::1231231234:assumed-role/AssumedRole-us-east-2/123123123456",
                "invokedBy": "cloudformation.amazonaws.com",
                "principalId": "AROAVKVYIOO7JN7TN7NSA:123123123456",
                "sessionContext": {
                    "attributes": {"creationDate": "2022-12-11T19:42:54Z", "mfaAuthenticated": "false"},
                    "sessionIssuer": {
                        "accountId": "1231231234",
                        "arn": "arn:aws:iam::1231231234:role/PAssumedRole-us-east-2",
                        "principalId": "AROAVKVYIOO7JN7TN7NSA",
                        "type": "Role",
                        "userName": "AssumedRole-us-east-2",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
]


@panther_managed
class AWSIAMGroupReadOnlyEvents(Rule):
    default_description = (
        "This rule captures multiple read/list events related to IAM group management in AWS Cloudtrail."
    )
    display_name = "AWS IAM Group Read Only Events"
    enabled = False
    default_reference = "https://attack.mitre.org/techniques/T1069/"
    default_runbook = "Examine other activities done by this user to determine whether or not activity is suspicious."
    default_severity = Severity.INFO
    tags = ["AWS", "Cloudtrail", "Configuration Required", "IAM", "MITRE"]
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.IAM.Group.Read.Only.Events-prototype"
    threshold = 2
    tests = awsiam_group_read_only_events_tests
    # arn allow list to suppress alerts
    ARN_ALLOW_LIST = []
    GROUP_ACTIONS = [
        "GetGroup",
        "GetGroupPolicy",
        "ListAttachedGroupPolicies",
        "ListGroupPolicies",
        "ListGroups",
        "ListGroupsForUser",
    ]

    def rule(self, event):
        event_arn = event.get("userIdentity", {}).get("arn", "<NO_ARN_FOUND>")
        # Return True if arn not in whitelist and event source is iam and event name is
        # present in read/list event_name list.
        if (
            event_arn not in self.ARN_ALLOW_LIST
            and event.get("eventSource", "<NO_EVENT_SOURCE_FOUND>") == "iam.amazonaws.com"
            and (event.get("eventName", "<NO_EVENT_NAME_FOUND>") in self.GROUP_ACTIONS)
        ):
            # continue on with analysis
            return True
        return False

    def title(self, event):
        return f"{event.get('userIdentity', {}).get('arn', '<NO_ARN_FOUND>')} IAM user group activity event found: {event.get('eventName', '<NO_EVENT_NAME_FOUND>')} in account {event.get('recipientAccountId', '<NO_RECIPIENT_ACCT_ID_FOUND>')} in region {event.get('awsRegion', '<NO_AWS_REGION_FOUND>')}."

    def dedup(self, event):
        # dedup via arn value
        return f"{event.get('userIdentity', {}).get('arn', '<NO_ARN_FOUND>')}"

    def alert_context(self, event):
        return aws_rule_context(event)
