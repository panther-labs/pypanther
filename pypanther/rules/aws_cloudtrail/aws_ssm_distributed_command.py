import datetime as dt
import json

from panther_core import PantherEvent
from panther_detection_helpers.caching import get_string_set, put_string_set

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSSSMDistributedCommand(Rule):
    id = "AWS.SSM.DistributedCommand-prototype"
    display_name = "AWS SSM Distributed Command"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0002:T1203"]}
    default_description = "Detect an attacker utilizing AWS Systems Manager (SSM) to execute commands through SendCommand on multiple EC2 instances.\n"
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ssm-send-command/\n"
    default_runbook = "Detetmine who issued the command, the command content and arguments, and which EC2 instances were affected. Determine the risk of an attacker creating a persistent point of access within one of the instances. Review behaviour logs for the EC2 instances (and their associated IAM roles).\n"
    summary_attributes = [
        "p_any_aws_account_ids",
        "p_any_aws_arns",
        "p_any_aws_instance_ids",
        "p_any_ip_addresses",
        "p_any_usernames",
    ]
    tags = ["AWS CloudTrail", "AWS SSM", "AWS EC2", "Execution: Exploitation for Client Execution", "Beta"]
    # Determine how separate instances need be commanded in order to trigger an alert
    INSTANCE_THRESHOLD = 2
    all_instance_ids = set()

    def rule(self, event: PantherEvent) -> bool:
        # Exclude events of the wrong type
        if event.get("eventName") != "SendCommand":
            return False
        # Determine if this actor accessed any other params in this account
        key = self.get_cache_key(event)
        cached_ids = self.get_cached_instance_ids(key)
        target_instance_ids = set(event.deep_get("requestParameters", "instanceIds", default=[]))
        # Determine if the cache needs updating with new entries
        self.all_instance_ids = cached_ids | target_instance_ids
        if self.all_instance_ids - cached_ids:
            # Only set the TTL if this is the first time we're adding to the cache
            #   Otherwise we'll be perpetually extending the lifespan of the cached data every time we
            #   add more.
            put_string_set(key, self.all_instance_ids, epoch_seconds=3600 if not cached_ids else None)
        # Check combined number of params
        return len(self.all_instance_ids) > self.INSTANCE_THRESHOLD

    def title(self, event: PantherEvent) -> str:
        actor = event.udm("actor_user")
        account_name = lookup_aws_account_name(event.get("recipientAccountId"))
        return f"Commands distributed to many EC2 instances by [{actor}] in [{account_name}]"

    def severity(self, event: PantherEvent) -> str:
        # Demote to LOW if attempt was denied
        if not aws_cloudtrail_success(event):
            return "LOW"
        return "DEFAULT"

    def alert_context(self, event: PantherEvent) -> dict:
        context = aws_rule_context(event)
        context.update({"instanceIds": list(self.all_instance_ids)})
        return context

    def get_cache_key(self, event) -> str:
        """
        Use the field values in the event to generate a cache key unique to this actor and
        account ID.
        """
        offset = dt.datetime.fromisoformat(event["p_event_time"]).timestamp() // 3600 * 3600
        actor = event.udm("actor_user")
        account = event.get("recipientAccountId")
        rule_id = "AWS.SSM.DistributedCommand"
        return f"{rule_id}-{account}-{actor}-{offset}"

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
            name="Send Command to Many Instances at Once",
            expected_result=True,
            mocks=[
                RuleMock(object_name="get_string_set", return_value="[]"),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-02-19 16:32:39.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-02-19 16:35:54.509896629",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "ceaea85a-6db9-4595-9842-d904fce2f047",
                "eventName": "SendCommand",
                "eventSource": "ssm.amazonaws.com",
                "eventTime": "2025-02-19 16:32:39.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "c41499e3-c04c-48e7-9da9-ef63d0868553",
                "requestParameters": {
                    "documentName": "AWS-RunShellScript",
                    "instanceIds": ["i-006e4c07b5fba8ad2", "i-01bf673280e708b0d", "i-020001cca1a2f2628"],
                    "interactive": False,
                    "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
                },
                "responseElements": {
                    "command": {
                        "alarmConfiguration": {"alarms": [], "ignorePollAlarmFailure": False},
                        "clientName": "",
                        "clientSourceId": "",
                        "cloudWatchOutputConfig": {"cloudWatchLogGroupName": "", "cloudWatchOutputEnabled": False},
                        "commandId": "f49a1fe5-d12b-4ac0-98bc-0e4bd83d70c0",
                        "comment": "",
                        "completedCount": 0,
                        "deliveryTimedOutCount": 0,
                        "documentName": "AWS-RunShellScript",
                        "documentVersion": "$DEFAULT",
                        "errorCount": 0,
                        "expiresAfter": "Feb 19, 2025, 6:32:39 PM",
                        "hasCancelCommandSignature": False,
                        "hasSendCommandSignature": False,
                        "instanceIds": ["i-006e4c07b5fba8ad2", "i-01bf673280e708b0d", "i-020001cca1a2f2628"],
                        "interactive": False,
                        "maxConcurrency": "50",
                        "maxErrors": "0",
                        "notificationConfig": {"notificationArn": "", "notificationEvents": [], "notificationType": ""},
                        "outputS3BucketName": "",
                        "outputS3KeyPrefix": "",
                        "outputS3Region": "us-west-2",
                        "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
                        "requestedDateTime": "Feb 19, 2025, 4:32:39 PM",
                        "serviceRole": "",
                        "status": "Pending",
                        "statusDetails": "Pending",
                        "targetCount": 3,
                        "targets": [],
                        "timeoutSeconds": 3600,
                        "triggeredAlarms": [],
                    },
                },
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ssm.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "sample-user-agent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY_ID",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-19T16:29:24Z", "mfaAuthenticated": "false"},
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
            name="Single Command Send, Many Cached IDs",
            expected_result=True,
            mocks=[
                RuleMock(object_name="get_string_set", return_value="[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]"),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-02-19 16:32:39.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-02-19 16:35:54.509896629",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "ceaea85a-6db9-4595-9842-d904fce2f047",
                "eventName": "SendCommand",
                "eventSource": "ssm.amazonaws.com",
                "eventTime": "2025-02-19 16:32:39.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "c41499e3-c04c-48e7-9da9-ef63d0868553",
                "requestParameters": {
                    "documentName": "AWS-RunShellScript",
                    "instanceIds": ["i-006e4c07b5fba8ad2"],
                    "interactive": False,
                    "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
                },
                "responseElements": {
                    "command": {
                        "alarmConfiguration": {"alarms": [], "ignorePollAlarmFailure": False},
                        "clientName": "",
                        "clientSourceId": "",
                        "cloudWatchOutputConfig": {"cloudWatchLogGroupName": "", "cloudWatchOutputEnabled": False},
                        "commandId": "f49a1fe5-d12b-4ac0-98bc-0e4bd83d70c0",
                        "comment": "",
                        "completedCount": 0,
                        "deliveryTimedOutCount": 0,
                        "documentName": "AWS-RunShellScript",
                        "documentVersion": "$DEFAULT",
                        "errorCount": 0,
                        "expiresAfter": "Feb 19, 2025, 6:32:39 PM",
                        "hasCancelCommandSignature": False,
                        "hasSendCommandSignature": False,
                        "instanceIds": ["i-006e4c07b5fba8ad2"],
                        "interactive": False,
                        "maxConcurrency": "50",
                        "maxErrors": "0",
                        "notificationConfig": {"notificationArn": "", "notificationEvents": [], "notificationType": ""},
                        "outputS3BucketName": "",
                        "outputS3KeyPrefix": "",
                        "outputS3Region": "us-west-2",
                        "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
                        "requestedDateTime": "Feb 19, 2025, 4:32:39 PM",
                        "serviceRole": "",
                        "status": "Pending",
                        "statusDetails": "Pending",
                        "targetCount": 3,
                        "targets": [],
                        "timeoutSeconds": 3600,
                        "triggeredAlarms": [],
                    },
                },
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ssm.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "sample-user-agent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY_ID",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-19T16:29:24Z", "mfaAuthenticated": "false"},
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
            name="Single Command Send, No Cached IDs",
            expected_result=False,
            mocks=[
                RuleMock(object_name="get_string_set", return_value="[]"),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-02-19 16:32:39.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-02-19 16:35:54.509896629",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "ceaea85a-6db9-4595-9842-d904fce2f047",
                "eventName": "SendCommand",
                "eventSource": "ssm.amazonaws.com",
                "eventTime": "2025-02-19 16:32:39.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "111122223333",
                "requestID": "c41499e3-c04c-48e7-9da9-ef63d0868553",
                "requestParameters": {
                    "documentName": "AWS-RunShellScript",
                    "instanceIds": ["i-006e4c07b5fba8ad2"],
                    "interactive": False,
                    "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
                },
                "responseElements": {
                    "command": {
                        "alarmConfiguration": {"alarms": [], "ignorePollAlarmFailure": False},
                        "clientName": "",
                        "clientSourceId": "",
                        "cloudWatchOutputConfig": {"cloudWatchLogGroupName": "", "cloudWatchOutputEnabled": False},
                        "commandId": "f49a1fe5-d12b-4ac0-98bc-0e4bd83d70c0",
                        "comment": "",
                        "completedCount": 0,
                        "deliveryTimedOutCount": 0,
                        "documentName": "AWS-RunShellScript",
                        "documentVersion": "$DEFAULT",
                        "errorCount": 0,
                        "expiresAfter": "Feb 19, 2025, 6:32:39 PM",
                        "hasCancelCommandSignature": False,
                        "hasSendCommandSignature": False,
                        "instanceIds": ["i-006e4c07b5fba8ad2"],
                        "interactive": False,
                        "maxConcurrency": "50",
                        "maxErrors": "0",
                        "notificationConfig": {"notificationArn": "", "notificationEvents": [], "notificationType": ""},
                        "outputS3BucketName": "",
                        "outputS3KeyPrefix": "",
                        "outputS3Region": "us-west-2",
                        "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
                        "requestedDateTime": "Feb 19, 2025, 4:32:39 PM",
                        "serviceRole": "",
                        "status": "Pending",
                        "statusDetails": "Pending",
                        "targetCount": 3,
                        "targets": [],
                        "timeoutSeconds": 3600,
                        "triggeredAlarms": [],
                    },
                },
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ssm.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "sample-user-agent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY_ID",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-19T16:29:24Z", "mfaAuthenticated": "false"},
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
                "p_event_time": "2025-02-19 18:00:45.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2025-02-19 18:05:54.395474849",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "447414b9-8516-4470-9e3a-f55067602ff0",
                "eventName": "DescribeInstances",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2025-02-19 18:00:45.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "c44720ce-1853-41c8-96b0-06dac0284963",
                "requestParameters": {
                    "filterSet": {},
                    "instancesSet": {"items": [{"instanceId": "i-09c2e8f99d245cc69"}]},
                },
                "sourceIPAddress": "eks.amazonaws.com",
                "userAgent": "eks.amazonaws.com",
                "userIdentity": {
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/SessionId",
                    "invokedBy": "eks.amazonaws.com",
                    "principalId": "SAMPLE_PRINCIPAL_ID:SessionId",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-19T17:55:44Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
