import datetime as dt
import json

from panther_core import PantherEvent
from panther_detection_helpers.caching import get_string_set, put_string_set

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSEC2MultiInstanceConnect(Rule):
    id = "AWS.EC2.MultiInstanceConnect-prototype"
    display_name = "AWS EC2 Multi Instance Connect"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0008:T1021.005"]}
    default_description = "Detect when an attacker pushes an SSH public key to multiple EC2 instances.\n"
    default_reference = (
        "https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-instance-connect/\n"
    )
    default_runbook = "Followup with the actor to determine if the SSH key is genuine. Consider using a different SSH key for each instance.\n"
    summary_attributes = ["p_any_actor_ids", "p_any_aws_account_ids", "p_any_aws_instance_ids", "p_any_usernames"]
    tags = ["AWS CloudTrail", "Lateral Movement", "Remote Services", "SSH", "Lateral Movement:Remote Services", "Beta"]

    def rule(self, event: PantherEvent) -> bool:
        if not (aws_cloudtrail_success(event) and event.get("eventName") == "SendSSHPublicKey"):
            return False
        offset = dt.datetime.fromisoformat(event["p_event_time"]).timestamp() // 3600 * 3600
        key = f"{event.deep_get('requestParameters', 'sSHPublicKey')}-{offset}"
        if not key:
            return False
        target_instance_id = event.deep_get("requestParameters", "instanceId")
        cached_instance_ids = self.get_cached_instance_ids(key)
        if len(cached_instance_ids) == 0:
            put_string_set(key, set(target_instance_id), epoch_seconds=3600)
            return False
        if target_instance_id not in cached_instance_ids:
            cached_instance_ids.add(target_instance_id)
            put_string_set(key, cached_instance_ids)
            return True
        return False

    def title(self, event: PantherEvent) -> str:
        actor = event.udm("actor_user")
        account_name = lookup_aws_account_name(event.get("recipientAccountId"))
        return f"{actor} uploaded an SSH Key to multiple instances in {account_name}"

    def dedup(self, event: PantherEvent) -> str:
        # Dedup based on the public SSH key
        return event.deep_get("requestParameters", "sSHPublicKey")

    def alert_context(self, event: PantherEvent) -> dict:
        context = aws_rule_context(event)
        context["instanceId"] = event.deep_get("requestParameters", "instanceId", default="<UNKNOWN EC2 INSTANCE ID>")
        return context

    def get_cached_instance_ids(self, key: str) -> set[str]:
        """
        Get any previously cached parameter names. Included automatic converstion from string in
        the case of a unit test mock.
        """
        cached_ids = get_string_set(key, force_ttl_check=True)
        if isinstance(cached_ids, str):
            # This is a unit test
            cached_ids = set(json.loads(cached_ids))
        return cached_ids

    tests = [
        RuleTest(
            name="Public SSH Key Sent Successfully to Multiple Instances",
            expected_result=True,
            mocks=[
                RuleMock(object_name="get_string_set", return_value='["i-other-id"]'),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-01-13 19:58:59.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-01-13 20:05:54.575569351",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "d6d05dd2-d03d-4dce-a88c-02b6a567d889",
                "eventName": "SendSSHPublicKey",
                "eventSource": "ec2-instance-connect.amazonaws.com",
                "eventTime": "2025-01-13 19:58:59.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "25eac5d1-cd24-4156-a49b-f2bf3a20ec9d",
                "requestParameters": {
                    "instanceId": "i-abcdef01234567890",
                    "instanceOSUser": "ec2-user",
                    "sSHPublicKey": "ssh-ed25519 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                },
                "responseElements": {"requestId": "25eac5d1-cd24-4156-a49b-f2bf3a20ec9d", "success": True},
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "ec2-instance-connect.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "stratus-red-team_8b255a24-d33d-4750-bd4b-4007124741df",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-01-13T19:21:25Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Public SSH Key Sent Successfully to Same Instance",
            expected_result=False,
            mocks=[
                RuleMock(object_name="get_string_set", return_value='["i-abcdef01234567890"]'),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-01-13 19:58:59.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-01-13 20:05:54.575569351",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "d6d05dd2-d03d-4dce-a88c-02b6a567d889",
                "eventName": "SendSSHPublicKey",
                "eventSource": "ec2-instance-connect.amazonaws.com",
                "eventTime": "2025-01-13 19:58:59.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "25eac5d1-cd24-4156-a49b-f2bf3a20ec9d",
                "requestParameters": {
                    "instanceId": "i-abcdef01234567890",
                    "instanceOSUser": "ec2-user",
                    "sSHPublicKey": "ssh-ed25519 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                },
                "responseElements": {"requestId": "25eac5d1-cd24-4156-a49b-f2bf3a20ec9d", "success": True},
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "ec2-instance-connect.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "stratus-red-team_8b255a24-d33d-4750-bd4b-4007124741df",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-01-13T19:21:25Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Public SSH Key Not Sent Successfully",
            expected_result=False,
            log={
                "p_event_time": "2025-01-13 20:46:57.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-01-13 20:55:54.194562429",
                "awsRegion": "us-west-2",
                "errorCode": "AccessDenied",
                "errorMessage": "User: arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt is not authorized to perform: ec2-instance-connect:SendSSHPublicKey on resource: arn:aws:ec2:us-west-2:111122223333:instance/i-abcdef01234567890 because no identity-based policy allows the ec2-instance-connect:SendSSHPublicKey action",
                "eventCategory": "Management",
                "eventID": "3ad527a2-8799-4561-8def-963a6dcdbbb5",
                "eventName": "SendSSHPublicKey",
                "eventSource": "ec2-instance-connect.amazonaws.com",
                "eventTime": "2025-01-13 20:46:57.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "cd8f31b6-a30f-4b14-a06a-3b41012228f3",
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "ec2-instance-connect.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "stratus-red-team_95b154bb-bcb2-4582-82f4-b3dbb6cfc1d9",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-01-13T20:46:53Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Unrelated Event",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "1111:tester",
                    "arn": "arn:aws:sts::123456789012:assumed-role/tester",
                    "accountId": "123456789012",
                    "accessKeyId": "1",
                    "sessionContext": {
                        "attributes": {"mfaAuthenticated": "true", "creationDate": "2019-01-01T00:00:00Z"},
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "1111",
                            "arn": "arn:aws:iam::123456789012:role/tester",
                            "accountId": "123456789012",
                            "userName": "tester",
                        },
                    },
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "CreateNetworkAclEntry",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "111.111.111.111",
                "userAgent": "console.ec2.amazonaws.com",
                "requestParameters": {
                    "networkAclId": "acl-1",
                    "ruleNumber": 500,
                    "egress": True,
                    "ruleAction": "allow",
                    "icmpTypeCode": {},
                    "portRange": {},
                    "aclProtocol": "-1",
                    "cidrBlock": "0.0.0.0/0",
                },
                "responseElements": {"requestID": "1", "_return": True},
                "requestID": "1",
                "eventID": "1",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
            },
        ),
    ]
