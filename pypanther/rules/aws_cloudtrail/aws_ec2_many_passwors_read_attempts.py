from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSEC2ManyPasswordReadAttempts(Rule):
    id = "AWS.EC2.ManyPasswordReadAttempts-prototype"
    display_name = "AWS EC2 Many Password Read Attempts"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0006:T1555"]}
    default_description = "An actor in AWS has made many attempts to retrieve EC2 passwords. It is typically not necessary to retrieve EC2 passwords more than a few times an hour.\n"
    threshold = 3
    default_reference = (
        "https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-get-password-data/"
    )
    default_runbook = "Identify the actor and the EC2 instances for which the credential access attempts were made. Determine if the attempts have a valid reason."
    tags = [
        "AWS",
        "CloudTrail",
        "EC2",
        "Credential Access:Credentials from Password Stores",
        "Credential Access",
        "Credentials from Password Stores",
        "Beta",
    ]

    def rule(self, event: PantherEvent) -> bool:
        # Raise alert if this is a GetPasswordData event for an EC2 service
        return event.get("eventName") == "GetPasswordData" and event.get("eventSource") == "ec2.amazonaws.com"

    def title(self, event: PantherEvent) -> str:
        actor = event.udm("actor_user")
        return f"{actor} has made multiple requests for EC2 password data in the last hour"

    def dedup(self, event: PantherEvent) -> str:
        # Dedup events based on the principal ID
        return event.udm("actor_user")

    def severity(self, event: PantherEvent) -> str:
        # Return "INFO" severity if the password read attempts are unsuccessful
        if not aws_cloudtrail_success(event):
            return "INFO"
        return "DEFAULT"

    def alert_context(self, event: PantherEvent) -> dict:
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="Unsuccessful Attempt",
            expected_result=True,
            log={
                "p_event_time": "2024-12-11 21:45:56.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-12-11 21:50:54.495464364",
                "awsRegion": "us-west-2",
                "errorCode": "Client.UnauthorizedOperation",
                "errorMessage": "You are not authorized to perform this operation. User: arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins is not authorized to perform: ec2:GetPasswordData on resource: arn:aws:ec2:us-west-2:111122223333:instance/* because no identity-based policy allows the ec2:GetPasswordData action. Encoded authorization failure message: VbdJrM7j1Czq6HEj1lZpnU-AWGICaaPZQs1K_-9U3hQcFpXimBHYHwvg4SOc36ACu0GUYqWoSeX6_wI7ke3QxC0d1_Wv2XYLI96rYdMY2aWzdzwkIp__hUQQi-XqaHmp-QHOHiiJ31xqEkDZvyZXaO0BHhCpf8m7mIMeMaAB2CPtKhPj5NPGGkPc1f6rNFx0grhDkKZ3MrWBo65U4nRjzJrThuyK3146B1k1tWuQfI2_H-QMCuOl_aTIZ93xIeWFoIqKUWnD6-F68V8hhxHHXl0EhiFL9p7LAGvYTPXtJ1wEH1ve8iOW1S9ptI8CuFVP-Q7E7-NS45tIaheVJusaq3JtS03XAnKYC2NuVXnXBwbPNbNiQWH8LfSdgl43MZ5Q9Kin-tqCoA_Yskz0F_JNokjmIB2PKegJ5kANzHcb09u9sSqvgqKqpVHpfIDtjcI8LPzWjZyUNExaymEWOkE4HhtF19t1zyBvuoO6xgZtCyAx-6fsDSO8jpBZbLz9MsPmjhJLfp_yQPOF9ROIrBhvNCY_2tC7hyDDwdl11iNzHQvBaCjiLjE5PcoEchYWTHqlVHZ-yMA3",
                "eventCategory": "Management",
                "eventID": "9e2b3bf0-8f58-4d50-83af-b3175b68c2f8",
                "eventName": "GetPasswordData",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2024-12-11 21:45:56.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "b22ce7ac-297f-41b4-a92e-f4aa38668c6d",
                "requestParameters": {"instanceId": "i-abcdef1234567890"},
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "ec2.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "SampleUserAgent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "SAMPLE_PRINCIPAL_ID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-12-11T21:45:52Z", "mfaAuthenticated": "false"},
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
        RuleTest(
            name="Successful Attempt",
            expected_result=True,
            log={
                "p_event_time": "2024-11-21 22:46:18.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2024-11-21 22:50:54.241713629",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "73076737-1a1e-418b-94fd-cbde95a5859d",
                "eventName": "GetPasswordData",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2024-11-21 22:46:18.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.10",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "111122223333",
                "requestID": "6ed17b60-a576-4b71-91d3-b59a37b3c6f9",
                "requestParameters": {"instanceId": "i-abcdef1234567890"},
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "ec2.us-west-2.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "SampleUserAgent",
                "userIdentity": {
                    "accessKeyId": "SAMPLE_ACCESS_KEY",
                    "accountId": "111122223333",
                    "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/leroy.jenkins",
                    "principalId": "SAMPLE_PRINCIPAL_ID:leroy.jenkins",
                    "sessionContext": {
                        "attributes": {"creationDate": "2024-11-21T22:42:44Z", "mfaAuthenticated": "false"},
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
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventID": "044e210e-6c5e-3f3e-8f04-2311a826f287",
                "eventName": "AssumeRole",
                "eventSource": "sts.amazonaws.com",
                "eventTime": "2024-12-12 16:04:32.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": "True",
                "readOnly": "True",
                "recipientAccountId": "111122223333",
                "requestID": "82c13187-0cc9-445e-9862-65d3ee2c6b7d",
                "requestParameters": {
                    "durationSeconds": "900",
                    "roleArn": "arn:aws:iam::111122223333:role/SampleRole",
                    "roleSessionName": "SampleSession",
                },
                "resources": [
                    "{'accountId': '111122223333', 'arn': 'arn:aws:iam::111122223333:role/SampleRole', 'type': 'AWS::IAM::Role'}",
                ],
                "responseElements": {
                    "assumedRoleUser": {
                        "arn": "arn:aws:sts::111122223333:assumed-role/SampleRole/SampleSession",
                        "assumedRoleId": "SAMPLE_PRINCIPAL_ID:SampleSession",
                    },
                    "credentials": {
                        "accessKeyId": "SAMPLE_ACCESS_KEY",
                        "expiration": "Dec 12, 2024, 4:19:32 PM",
                        "sessionToken": "SampleSessionToken",
                    },
                },
                "sharedEventID": "fe4784a8-b3b8-4dac-a763-0476f4bef6e3",
                "sourceIPAddress": "1.2.3.4",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "sts.us-east-1.amazonaws.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "SampleUserAgent",
                "userIdentity": {
                    "accountId": "111122223333",
                    "principalId": "SAMPLE_PRINCIPAL_ID:lambda-name",
                    "type": "AWSAccount",
                },
            },
        ),
    ]
