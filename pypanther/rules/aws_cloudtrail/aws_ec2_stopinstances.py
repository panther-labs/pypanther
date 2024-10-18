from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSEC2StopInstances(Rule):
    id = "AWS.EC2.StopInstances-prototype"
    display_name = "CloudTrail EC2 StopInstances"
    create_alert = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["panther-signal"]
    default_severity = Severity.INFO
    default_description = "A CloudTrail instances were stopped. It makes further changes of instances possible\n"
    default_reference = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html"

    def rule(self, event):
        return all(
            [not event.get("errorCode"), not event.get("errorMessage"), event.get("eventName") == "StopInstances"],
        )

    def title(self, event):
        instances = [
            instance["instanceId"]
            for instance in event.deep_get("requestParameters", "instancesSet", "items", default=[])
        ]
        account = event.get("recipientAccountId")
        return f"EC2 instances {instances} stopped in account {account}."

    def alert_context(self, event):
        context = aws_rule_context(event)
        context["instance_ids"] = [
            instance["instanceId"]
            for instance in event.deep_get("requestParameters", "instancesSet", "items", default=[])
        ]
        return context

    tests = [
        RuleTest(
            name="CloudTrail Instances Were Stopped",
            expected_result=True,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "EXAMPLE6E4XEGITWATV6R",
                    "arn": "arn:aws:iam::777788889999:user/Nikki",
                    "accountId": "777788889999",
                    "accessKeyId": "AKIAI44QH8DHBEXAMPLE",
                    "userName": "Nikki",
                    "sessionContext": {
                        "sessionIssuer": {},
                        "webIdFederationData": {},
                        "attributes": {"creationDate": "2023-07-19T21:11:57Z", "mfaAuthenticated": "false"},
                    },
                },
                "eventTime": "2023-07-19T21:14:20Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "StopInstances",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "aws-cli/2.13.5 Python/3.11.4 Linux/4.14.255-314-253.539.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/ec2.stop-instances",
                "requestParameters": {
                    "instancesSet": {
                        "items": [{"instanceId": "i-EXAMPLE56126103cb"}, {"instanceId": "i-EXAMPLEaff4840c22"}],
                    },
                    "force": False,
                },
                "responseElements": {
                    "requestId": "c308a950-e43e-444e-afc1-EXAMPLE73e49",
                    "instancesSet": {
                        "items": [
                            {
                                "instanceId": "i-EXAMPLE56126103cb",
                                "currentState": {"code": 64, "name": "stopping"},
                                "previousState": {"code": 16, "name": "running"},
                            },
                            {
                                "instanceId": "i-EXAMPLEaff4840c22",
                                "currentState": {"code": 64, "name": "stopping"},
                                "previousState": {"code": 16, "name": "running"},
                            },
                        ],
                    },
                },
                "requestID": "c308a950-e43e-444e-afc1-EXAMPLE73e49",
                "eventID": "9357a8cc-a0eb-46a1-b67e-EXAMPLE19b14",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "777788889999",
                "eventCategory": "Management",
                "tlsDetails": {
                    "tlsVersion": "TLSv1.2",
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ec2.us-east-1.amazonaws.com",
                },
                "sessionCredentialFromConsole": "true",
            },
        ),
        RuleTest(
            name="CloudTrail Instances Were Started",
            expected_result=False,
            log={
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "EXAMPLE6E4XEGITWATV6R",
                    "arn": "arn:aws:iam::123456789012:user/Mateo",
                    "accountId": "123456789012",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "Mateo",
                    "sessionContext": {
                        "sessionIssuer": {},
                        "webIdFederationData": {},
                        "attributes": {"creationDate": "2023-07-19T21:11:57Z", "mfaAuthenticated": "false"},
                    },
                },
                "eventTime": "2023-07-19T21:17:28Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "StartInstances",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "aws-cli/2.13.5 Python/3.11.4 Linux/4.14.255-314-253.539.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/ec2.start-instances",
                "requestParameters": {
                    "instancesSet": {
                        "items": [{"instanceId": "i-EXAMPLE56126103cb"}, {"instanceId": "i-EXAMPLEaff4840c22"}],
                    },
                },
                "responseElements": {
                    "requestId": "e4336db0-149f-4a6b-844d-EXAMPLEb9d16",
                    "instancesSet": {
                        "items": [
                            {
                                "instanceId": "i-EXAMPLEaff4840c22",
                                "currentState": {"code": 0, "name": "pending"},
                                "previousState": {"code": 80, "name": "stopped"},
                            },
                            {
                                "instanceId": "i-EXAMPLE56126103cb",
                                "currentState": {"code": 0, "name": "pending"},
                                "previousState": {"code": 80, "name": "stopped"},
                            },
                        ],
                    },
                },
                "requestID": "e4336db0-149f-4a6b-844d-EXAMPLEb9d16",
                "eventID": "e755e09c-42f9-4c5c-9064-EXAMPLE228c7",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "123456789012",
                "eventCategory": "Management",
                "tlsDetails": {
                    "tlsVersion": "TLSv1.2",
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ec2.us-east-1.amazonaws.com",
                },
                "sessionCredentialFromConsole": "true",
            },
        ),
        RuleTest(
            name="Error Stopping CloudTrail Instances",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "errorCode": "SomeErrorCode",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "EXAMPLE6E4XEGITWATV6R",
                    "arn": "arn:aws:iam::777788889999:user/Nikki",
                    "accountId": "777788889999",
                    "accessKeyId": "AKIAI44QH8DHBEXAMPLE",
                    "userName": "Nikki",
                    "sessionContext": {
                        "sessionIssuer": {},
                        "webIdFederationData": {},
                        "attributes": {"creationDate": "2023-07-19T21:11:57Z", "mfaAuthenticated": "false"},
                    },
                },
                "eventTime": "2023-07-19T21:14:20Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "StopInstances",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.0",
                "userAgent": "aws-cli/2.13.5 Python/3.11.4 Linux/4.14.255-314-253.539.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/ec2.stop-instances",
                "requestParameters": {
                    "instancesSet": {
                        "items": [{"instanceId": "i-EXAMPLE56126103cb"}, {"instanceId": "i-EXAMPLEaff4840c22"}],
                    },
                    "force": False,
                },
                "requestID": "c308a950-e43e-444e-afc1-EXAMPLE73e49",
                "eventID": "9357a8cc-a0eb-46a1-b67e-EXAMPLE19b14",
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "777788889999",
                "eventCategory": "Management",
                "tlsDetails": {
                    "tlsVersion": "TLSv1.2",
                    "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                    "clientProvidedHostHeader": "ec2.us-east-1.amazonaws.com",
                },
                "sessionCredentialFromConsole": "true",
            },
        ),
    ]
