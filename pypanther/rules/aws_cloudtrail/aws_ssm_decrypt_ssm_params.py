import datetime as dt
import json

from panther_core import PantherEvent
from panther_detection_helpers.caching import get_string_set, put_string_set

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSSSMDecryptSSMParams(Rule):
    id = "AWS.SSM.DecryptSSMParams-prototype"
    display_name = "AWS Decrypt SSM Parameters"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0006:T1555"]}
    default_description = "Identify principles retrieving a high number of SSM Parameters of type 'SecretString'.\n"
    threshold = 10
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ssm-retrieve-securestring-parameters/\n"
    default_runbook = "Determine if the secrets accessed contain sensitive information. Consider suspecing access for the user identity until their intentions are verified. If any IAM credentials or similar were compromised, rotate them.\n"
    summary_attributes = ["sourceIpAddress", "p_alert_context.accessedParams"]
    tags = ["AWS CloudTrail", "Credential Access: Credentials from Password Stores", "Beta"]
    # Determine how many secets must be accessed in order to trigger an alert
    PARAM_THRESHOLD = 10
    all_param_names = set()

    def rule(self, event: PantherEvent) -> bool:
        # Exclude events of the wrong type
        if not (
            event.get("eventName") in ("GetParameter", "GetParameters")
            and event.deep_get("requestParameters", "withDecryption")
        ):
            return False
        # Determine if this actor accessed any other params in this account
        key = self.get_cache_key(event)
        cached_params = self.get_cached_param_names(key)
        accessed_params = self.get_param_names(event)
        # Determine if the cache needs updating with new entries
        self.all_param_names = cached_params | accessed_params
        if self.all_param_names - cached_params:
            # Only set the TTL if this is the first time we're adding to the cache
            #   Otherwise we'll be perpetually extending the lifespan of the cached data every time we
            #   add more.
            put_string_set(key, self.all_param_names, epoch_seconds=3600 if not cached_params else None)
        # Check combined number of params
        return len(self.all_param_names) > self.PARAM_THRESHOLD

    def title(self, event: PantherEvent) -> str:
        actor = event.udm("actor_user")
        account_name = lookup_aws_account_name(event.get("recipientAccountId"))
        return f"Excessive SSM parameter decryption by [{actor}] in [{account_name}]"

    def severity(self, event: PantherEvent) -> str:
        # Demote to LOW if attempt was denied
        if not aws_cloudtrail_success(event):
            return "LOW"
        return "DEFAULT"

    def alert_context(self, event: PantherEvent) -> dict:
        context = aws_rule_context(event)
        context.update({"accessedParams": list(self.all_param_names)})
        return context

    def get_cache_key(self, event) -> str:
        """
        Use the field values in the event to generate a cache key unique to this actor and
        account ID.
        """
        offset = dt.datetime.fromisoformat(event["p_event_time"]).timestamp() // 3600 * 3600
        actor = event.udm("actor_user")
        account = event.get("recipientAccountId")
        rule_id = "AWS.SSM.DecryptSSMParams"
        return f"{rule_id}-{account}-{actor}-{offset}"

    def get_param_names(self, event) -> set[str]:
        """Returns the accessed SSM Param names."""
        # Params could be either a list or a single entry
        params = set(event.deep_get("requestParameters", "names", default=[]))
        if single_param := event.deep_get("requestParameters", "name"):
            params.add(single_param)
        return params

    def get_cached_param_names(self, key: str) -> set[str]:
        """
        Get any previously cached parameter names. Included automatic converstion from string in
        the case of a unit test mock.
        """
        cached_params = get_string_set(key, force_ttl_check=True)
        if isinstance(cached_params, str):
            # This is a unit test
            cached_params = set(json.loads(cached_params))
        return cached_params

    tests = [
        RuleTest(
            name="Single Secret Accessed in Single Event",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="get_string_set",
                    return_value='["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]',
                ),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-02-14 19:43:09.000000000",
                "p_log_type": "AWS.CloudTrail",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "587e6d58-a653-4fd9-859f-367dc1bad98c",
                "eventName": "GetParameter",
                "eventSource": "ssm.amazonaws.com",
                "eventTime": "2025-02-14 19:43:09.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "a1f28efd-9f5b-4a13-9878-86f57de594dc",
                "requestParameters": {"name": "/credentials/stratus-red-team/credentials-25", "withDecryption": True},
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-25",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ssm.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "example-user-agent",
                "userIdentity": {
                    "accessKeyId": "EXAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-14T19:42:05Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Multiple Secrets Accessed in Same Event",
            expected_result=True,
            mocks=[
                RuleMock(object_name="get_string_set", return_value="[]"),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-02-14 19:42:57.000000000",
                "p_log_type": "AWS.CloudTrail",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "ce59873d-6a27-4fa4-afc1-088fceba71e4",
                "eventName": "GetParameters",
                "eventSource": "ssm.amazonaws.com",
                "eventTime": "2025-02-14 19:42:57.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "b6cb0ea5-2366-47c3-a4e5-acc31bc6882a",
                "requestParameters": {
                    "names": [
                        "/credentials/stratus-red-team/credentials-10",
                        "/credentials/stratus-red-team/credentials-11",
                        "/credentials/stratus-red-team/credentials-12",
                        "/credentials/stratus-red-team/credentials-15",
                        "/credentials/stratus-red-team/credentials-24",
                        "/credentials/stratus-red-team/credentials-30",
                        "/credentials/stratus-red-team/credentials-31",
                        "/credentials/stratus-red-team/credentials-32",
                        "/credentials/stratus-red-team/credentials-36",
                        "/credentials/stratus-red-team/credentials-40",
                        "/credentials/stratus-red-team/credentials-41",
                    ],
                    "withDecryption": True,
                },
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-10",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-11",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-12",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-15",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-24",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-30",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-31",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-32",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-36",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-40",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ssm.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "example-user-agent",
                "userIdentity": {
                    "accessKeyId": "EXAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-14T19:42:05Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Multiple Secrets Accessed in Same Event With Prior Cached Parameters",
            expected_result=True,
            mocks=[
                RuleMock(object_name="get_string_set", return_value='["a", "b", "c", "d", "e", "f"]'),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-02-14 19:42:57.000000000",
                "p_log_type": "AWS.CloudTrail",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "ce59873d-6a27-4fa4-afc1-088fceba71e4",
                "eventName": "GetParameters",
                "eventSource": "ssm.amazonaws.com",
                "eventTime": "2025-02-14 19:42:57.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "b6cb0ea5-2366-47c3-a4e5-acc31bc6882a",
                "requestParameters": {
                    "names": [
                        "/credentials/stratus-red-team/credentials-10",
                        "/credentials/stratus-red-team/credentials-11",
                        "/credentials/stratus-red-team/credentials-12",
                        "/credentials/stratus-red-team/credentials-15",
                        "/credentials/stratus-red-team/credentials-24",
                    ],
                    "withDecryption": True,
                },
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-10",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-11",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-12",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-15",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-24",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-30",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-31",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-32",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-36",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-40",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ssm.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "example-user-agent",
                "userIdentity": {
                    "accessKeyId": "EXAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-14T19:42:05Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Accessed Parameters Aren't Encrypted",
            expected_result=False,
            mocks=[
                RuleMock(object_name="get_string_set", return_value="[]"),
                RuleMock(object_name="put_string_set", return_value=""),
            ],
            log={
                "p_event_time": "2025-02-14 19:42:57.000000000",
                "p_log_type": "AWS.CloudTrail",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "ce59873d-6a27-4fa4-afc1-088fceba71e4",
                "eventName": "GetParameters",
                "eventSource": "ssm.amazonaws.com",
                "eventTime": "2025-02-14 19:42:57.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "b6cb0ea5-2366-47c3-a4e5-acc31bc6882a",
                "requestParameters": {
                    "names": [
                        "/credentials/stratus-red-team/credentials-10",
                        "/credentials/stratus-red-team/credentials-11",
                        "/credentials/stratus-red-team/credentials-12",
                        "/credentials/stratus-red-team/credentials-15",
                        "/credentials/stratus-red-team/credentials-24",
                        "/credentials/stratus-red-team/credentials-30",
                        "/credentials/stratus-red-team/credentials-31",
                        "/credentials/stratus-red-team/credentials-32",
                        "/credentials/stratus-red-team/credentials-36",
                        "/credentials/stratus-red-team/credentials-40",
                        "/credentials/stratus-red-team/credentials-41",
                    ],
                },
                "resources": [
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-10",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-11",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-12",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-15",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-24",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-30",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-31",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-32",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-36",
                    },
                    {
                        "accountId": "111122223333",
                        "arn": "arn:aws:ssm:us-west-2:111122223333:parameter/credentials/stratus-red-team/credentials-40",
                    },
                ],
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ssm.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "example-user-agent",
                "userIdentity": {
                    "accessKeyId": "EXAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-14T19:42:05Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
                            "principalId": "SAMPLE_PRINCIPAL_ID",
                            "type": "Role",
                            "userName": "SampleRole",
                        },
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Unrelated Event",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "6c6de06f-eb03-44cd-a95f-928a780ce28a",
                "eventName": "DescribeParameters",
                "eventSource": "ssm.amazonaws.com",
                "eventTime": "2025-02-14 19:43:07.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.11",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "9ea104aa-d9af-415f-9c56-b7bb98c7c73f",
                "requestParameters": {
                    "parameterFilters": [
                        {"key": "Name", "option": "Equals", "values": ["/credentials/stratus-red-team/credentials-1"]},
                    ],
                },
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ssm.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.2",
                },
                "userAgent": "example-user-agent",
                "userIdentity": {
                    "accessKeyId": "EXAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/bobson.dugnutt",
                    "principalId": "SAMPLE_PRINCIPAL_ID:bobson.dugnutt",
                    "sessionContext": {
                        "attributes": {"creationDate": "2025-02-14T19:42:05Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-west-2/SampleRole",
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
