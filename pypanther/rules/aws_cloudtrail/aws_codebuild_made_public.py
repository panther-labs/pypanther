from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context, lookup_aws_account_name


@panther_managed
class AWSCloudTrailCodebuildProjectMadePublic(Rule):
    id = "AWS.CloudTrail.CodebuildProjectMadePublic-prototype"
    display_name = "CodeBuild Project made Public"
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0010:T1567"]}
    tags = ["AWS", "Security Control", "Exfiltration:Exfiltration Over Web Service"]
    default_severity = Severity.HIGH
    default_description = "An AWS CodeBuild Project was made publicly accessible\n"
    default_runbook = "TBD"
    default_reference = "https://docs.aws.amazon.com/codebuild/latest/userguide/public-builds.html"
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        return (
            event["eventName"] == "UpdateProjectVisibility"
            and event.deep_get("requestParameters", "projectVisibility") == "PUBLIC_READ"
        )

    def title(self, event):
        return f"AWS CodeBuild Project made Public by {event.deep_get('userIdentity', 'arn')} in account {lookup_aws_account_name(event.deep_get('recipientAccountId'))}"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="CodeBuild Project Made Public",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "111111111111",
                    "arn": "arn:aws:sts::111122223333:assumed-role/MakeStuffPublic",
                    "accountId": "111122223333",
                    "accessKeyId": "ASIAXXXXXXXXXXXX",
                    "sessionContext": {
                        "sessionIssuer": {},
                        "webIdFederationData": {},
                        "attributes": {"creationDate": "2021-08-18T14:54:10Z", "mfaAuthenticated": "false"},
                    },
                },
                "eventTime": "2021-08-18T14:54:53Z",
                "eventSource": "codebuild.amazonaws.com",
                "eventName": "UpdateProjectVisibility",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-internal/3 aws-sdk-java/1.11.1030 Linux/5.4.116-64.217.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.302-b08 java/1.8.0_302 vendor/Oracle_Corporation cfg/retry-mode/legacy",
                "requestParameters": {
                    "projectVisibility": "PUBLIC_READ",
                    "projectArn": "arn:aws:codebuild:us-east-1:111122223333:project/testproject1234",
                    "resourceAccessRole": "arn:aws:iam::111122223333:role/service-role/test",
                },
                "responseElements": None,
                "requestID": "4397365f-c790-4c23-9fe6-97e13a16ea84",
                "eventID": "982f8066-640d-40fb-b433-ba15e14fee40",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "111122223333",
                "eventCategory": "Management",
            },
        ),
        RuleTest(
            name="CodeBuild Project Made Private",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "111111111111",
                    "arn": "arn:aws:sts::111122223333:assumed-role/MakeStuffPublic",
                    "accountId": "111122223333",
                    "accessKeyId": "ASIAXXXXXXXXXXXX",
                    "sessionContext": {
                        "sessionIssuer": {},
                        "webIdFederationData": {},
                        "attributes": {"creationDate": "2021-08-18T14:54:10Z", "mfaAuthenticated": "false"},
                    },
                },
                "eventTime": "2021-08-18T14:54:53Z",
                "eventSource": "codebuild.amazonaws.com",
                "eventName": "UpdateProjectVisibility",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-internal/3 aws-sdk-java/1.11.1030 Linux/5.4.116-64.217.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.302-b08 java/1.8.0_302 vendor/Oracle_Corporation cfg/retry-mode/legacy",
                "requestParameters": {
                    "projectVisibility": "PRIVATE",
                    "projectArn": "arn:aws:codebuild:us-east-1:111122223333:project/testproject1234",
                    "resourceAccessRole": "arn:aws:iam::111122223333:role/service-role/test",
                },
                "responseElements": None,
                "requestID": "4397365f-c790-4c23-9fe6-97e13a16ea84",
                "eventID": "982f8066-640d-40fb-b433-ba15e14fee40",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "111122223333",
                "eventCategory": "Management",
            },
        ),
        RuleTest(
            name="Not a UpdateProjectVisibility event",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "111111111111",
                    "arn": "arn:aws:sts::111122223333:assumed-role/MakeStuffPublic",
                    "accountId": "111122223333",
                    "accessKeyId": "ASIAXXXXXXXXXXXX",
                    "sessionContext": {
                        "sessionIssuer": {},
                        "webIdFederationData": {},
                        "attributes": {"creationDate": "2021-08-18T14:54:10Z", "mfaAuthenticated": "false"},
                    },
                },
                "eventTime": "2021-08-18T14:54:53Z",
                "eventSource": "codebuild.amazonaws.com",
                "eventName": "CreateProject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.1.1.1",
                "userAgent": "aws-internal/3 aws-sdk-java/1.11.1030 Linux/5.4.116-64.217.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.302-b08 java/1.8.0_302 vendor/Oracle_Corporation cfg/retry-mode/legacy",
                "responseElements": None,
                "requestID": "4397365f-c790-4c23-9fe6-97e13a16ea84",
                "eventID": "982f8066-640d-40fb-b433-ba15e14fee40",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "111122223333",
                "eventCategory": "Management",
            },
        ),
    ]
