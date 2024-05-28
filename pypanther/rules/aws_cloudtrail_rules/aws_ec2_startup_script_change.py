from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import aws_rule_context, deep_get
from pypanther.log_types import LogType

awsec2_startup_script_change_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="ModifyInstanceAttribute-NoUserData",
        ExpectedResult=False,
        Log={
            "awsregion": "us-east-1",
            "eventid": "abc-123",
            "eventname": "ModifyInstanceAttribute",
            "eventsource": "ec2.amazonaws.com",
            "eventtime": "2022-07-17 04:50:23",
            "eventtype": "AwsApiCall",
            "eventversion": "1.08",
            "p_any_aws_instance_ids": ["testinstanceid"],
            "p_event_time": "2022-07-17 04:50:23",
            "p_log_type": "AWS.CloudTrail",
            "p_parse_time": "2022-07-17 04:55:11.788",
            "requestParameters": {
                "instanceId": "testinstanceid",
                "instanceType": {"value": "t3.nano"},
            },
        },
    ),
    PantherRuleTest(
        Name="ModifyInstanceAttributeUserdata",
        ExpectedResult=True,
        Log={
            "awsRegion": "us-east-2",
            "eventCategory": "Management",
            "eventName": "ModifyInstanceAttribute",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2022-09-30 15:11:25.000000000",
            "eventType": "AwsApiCall",
            "eventVersion": "1.08",
            "managementEvent": True,
            "readOnly": False,
            "recipientAccountId": "0123456789",
            "requestID": "example-id",
            "requestParameters": {
                "instanceId": "i-012345abcde",
                "userData": "<sensitiveDataRemoved>",
            },
            "responseElements": {"_return": True, "requestId": "012345abcdef"},
            "sourceIPAddress": "1.2.3.4",
            "tlsDetails": {
                "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                "clientProvidedHostHeader": "ec2.us-east-2.amazonaws.com",
                "tlsVersion": "TLSv1.2",
            },
            "userAgent": "aws sdk",
            "userIdentity": {
                "accessKeyId": "ABCDEXAMPLE123",
                "accountId": "0123456789",
                "arn": "arn:aws:sts::0123456789:assumed-role/Role-us-1/CodeBuild",
                "principalId": "ABCDEXAMPLE:CodeBuild",
                "sessionContext": {
                    "attributes": {
                        "creationDate": "2022-09-30T14:52:26Z",
                        "mfaAuthenticated": "false",
                    },
                    "sessionIssuer": {
                        "accountId": "0123456789",
                        "arn": "arn:aws:iam::0123456789:role/CodeBuild-US-East",
                        "principalId": "AROAQUW22FGSKBTQ7R5HP",
                        "type": "Role",
                        "userName": "CodeBuild-US-East",
                    },
                    "webIdFederationData": {},
                },
                "type": "AssumedRole",
            },
        },
    ),
    PantherRuleTest(
        Name="NoModifyInstanceAttribute",
        ExpectedResult=False,
        Log={
            "awsregion": "us-east-1",
            "eventid": "abc-123",
            "eventname": "ModifyImageAttribute",
            "eventsource": "ec2.amazonaws.com",
            "eventtime": "2022-07-17 04:50:23",
            "eventtype": "AwsApiCall",
            "eventversion": "1.08",
            "p_any_aws_instance_ids": ["testinstanceid"],
            "p_event_time": "2022-07-17 04:50:23",
            "p_log_type": "AWS.CloudTrail",
            "p_parse_time": "2022-07-17 04:55:11.788",
            "requestParameters": {
                "instanceId": "testinstanceid",
                "instanceType": {"value": "t3.nano"},
            },
        },
    ),
]


class AWSEC2StartupScriptChange(PantherRule):
    Description = "Detects changes to the EC2 instance startup script. The shell script will be executed as root/SYSTEM every time the specific instances are booted up."
    DisplayName = "AWS EC2 Startup Script Change"
    Reports = {"MITRE ATT&CK": ["TA0002:T1059"]}
    Reference = (
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html#user-data-shell-scripts"
    )
    Severity = PantherSeverity.High
    LogTypes = [LogType.AWS_CloudTrail]
    RuleID = "AWS.EC2.Startup.Script.Change-prototype"
    Tests = awsec2_startup_script_change_tests

    def rule(self, event):
        if event.get("eventName") == "ModifyInstanceAttribute" and deep_get(
            event, "requestParameters", "userData"
        ):
            return True
        return False

    def title(self, event):
        return f"[{deep_get(event, 'userIdentity', 'arn')}] modified the startup script for  [{deep_get(event, 'requestParameters', 'instanceId')}] in [{event.get('recipientAccountId')}] - [{event.get('awsRegion')}]"

    def dedup(self, event):
        return deep_get(event, "requestParameters", "instanceId")

    def alert_context(self, event):
        return aws_rule_context(event)
