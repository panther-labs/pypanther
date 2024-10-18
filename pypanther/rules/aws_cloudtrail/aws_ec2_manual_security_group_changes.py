from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context
from pypanther.helpers.base import pattern_match_list


@panther_managed
class AWSEC2ManualSecurityGroupChange(Rule):
    id = "AWS.EC2.ManualSecurityGroupChange-prototype"
    display_name = "AWS EC2 Manual Security Group Change"
    enabled = False
    log_types = [LogType.AWS_CLOUDTRAIL]
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    tags = ["AWS", "Security Control", "Configuration Required", "Defense Evasion:Impair Defenses"]
    default_severity = Severity.MEDIUM
    default_description = "An EC2 security group was manually updated without abiding by the organization's accepted processes. This rule expects organizations to either use the Console, CloudFormation, or Terraform, configurable in the rule's ALLOWED_USER_AGENTS.\n"
    default_runbook = "Identify the actor who changed the security group and validate it was legitimate"
    default_reference = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html"
    PROD_ACCOUNT_IDS = {"11111111111111", "112233445566"}
    SG_CHANGE_EVENTS = {
        "CreateSecurityGroup": {
            "fields": ["groupName", "vpcId"],
            "title": "New security group [{groupName}] created by {actor}",
        },
        "AuthorizeSecurityGroupIngress": {
            "fields": ["groupId"],
            "title": "User {actor} has updated security group [{groupId}]",
        },
        "AuthorizeSecurityGroupEgress": {
            "fields": ["groupId"],
            "title": "User {actor} has updated security group [{groupId}]",
        },
    }
    # 'console.ec2.amazonaws.com',
    # 'cloudformation.amazonaws.com',
    ALLOWED_USER_AGENTS = {"* HashiCorp/?.0 Terraform/*"}
    ALLOWED_ROLE_NAMES = {"Operator", "ContinousDeployment"}

    def rule(self, event):
        # Validate the deployment mechanism (Console, CloudFormation, or Terraform)
        # Validate the IAM Role used is in our acceptable list
        return aws_cloudtrail_success(event) and (
            event.get("eventName") in self.SG_CHANGE_EVENTS.keys()
            and event.get("recipientAccountId") in self.PROD_ACCOUNT_IDS
            and (
                not (
                    pattern_match_list(event.get("userAgent"), self.ALLOWED_USER_AGENTS)
                    and any(role in event.deep_get("userIdentity", "arn") for role in self.ALLOWED_ROLE_NAMES)
                )
            )
        )

    def dedup(self, event):
        return ":".join(
            event.deep_get("requestParameters", field, default="<UNKNOWN_FIELD>")
            for field in self.SG_CHANGE_EVENTS[event.get("eventName")]["fields"]
        )

    def title(self, event):
        title_fields = {
            field: event.deep_get("requestParameters", field, default="<UNKNOWN_FIELD>")
            for field in self.SG_CHANGE_EVENTS[event.get("eventName")]["fields"]
        }
        user = event.deep_get("userIdentity", "arn", default="<UNKNOWN_USER>").split("/")[-1]
        title_template = self.SG_CHANGE_EVENTS[event.get("eventName")]["title"]
        title_fields["actor"] = user
        return title_template.format(**title_fields)

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="AWS Console - Ingress SG Authorization",
            expected_result=True,
            log={
                "awsRegion": "us-west-2",
                "eventID": "504b492f-7832-406b-a4fd-45a13e48adc4",
                "eventName": "AuthorizeSecurityGroupIngress",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2021-01-24 04:55:45.000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "112233445566",
                "requestID": "91f34d65-513d-4e9f-a3de-e8d27f7ee4b2",
                "requestParameters": {
                    "groupId": "sg-04f0b44316f7d2471",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/16"}]},
                                "prefixListIds": {},
                                "fromPort": "443",
                                "toPort": "443",
                                "groups": {},
                                "ipProtocol": "tcp",
                                "ipv6Ranges": {},
                            },
                        ],
                    },
                },
                "responseElements": {"_return": True, "requestId": "91f34d65-513d-4e9f-a3de-e8d27f7ee4b2"},
                "sourceIPAddress": "136.25.37.134",
                "userAgent": "console.ec2.amazonaws.com",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalid": "ARORJ4ULULLE0EEJAAKDO:alan",
                    "arn": "arn:aws:sts::112233445566:assumed-role/TestAdmin/alan",
                    "accountid": "112233445566",
                    "accesskeyid": "ASIASWJRT64Z7ZLFLJNI",
                    "sessioncontext": {
                        "attributes": {"mfaauthenticated": "true", "creationdate": "2021-01-24T04:55:10Z"},
                        "sessionissuer": {
                            "type": "Role",
                            "principalid": "ARORJ4ULULLE0EEJAAKDO",
                            "arn": "arn:aws:iam::112233445566:role/TestAdmin",
                            "accountid": "112233445566",
                            "username": "TestAdmin",
                        },
                    },
                },
                "p_event_time": "2021-01-24 04:55:45.000",
                "p_parse_time": "2021-01-24 05:02:58.358",
                "p_log_type": "AWS.CloudTrail",
                "p_row_id": "1a57ff7ade26aaf5a1a4d7d20775",
                "p_source_id": "e55677c6-7ef5-4541-a443-0d0f17eec19f",
                "p_source_label": "CloudTrail Test",
                "p_any_ip_addresses": ["136.25.37.134"],
                "p_any_aws_account_ids": ["112233445566"],
                "p_any_aws_arns": [
                    "arn:aws:iam::112233445566:role/TestAdmin",
                    " arn:aws:sts::112233445566:assumed-role/TestAdmin/alan",
                ],
            },
        ),
        RuleTest(
            name="Terraform Security Group Creation",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AROAIZCYMDBM4SJU6XXXX:ryan@example.com",
                    "arn": "arn:aws:sts::112233445566:assumed-role/Operator/ryan@example.com",
                    "accountId": "112233445566",
                    "accessKeyId": "ASIAWDWBPTM3RJH7XXXX",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "AROAIZCYMDBM4SJU65M54",
                            "arn": "arn:aws:iam::112233445566:role/Operator",
                            "accountId": "112233445566",
                            "userName": "Operator",
                        },
                        "webIdFederationData": {},
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2020-04-30T23:50:12Z"},
                    },
                },
                "eventTime": "2020-04-30T23:51:06Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "CreateSecurityGroup",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "100.1.114.142",
                "userAgent": "aws-sdk-go/1.29.7 (go1.13.7; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.24 (+https://www.terraform.io)",
                "requestParameters": {
                    "groupName": "prod-webapp-webserver-security",
                    "groupDescription": "prod-webapp-webserver Security SG",
                    "vpcId": "vpc-a1a044c7",
                },
                "responseElements": {
                    "requestId": "594fe3e3-0f74-4085-9336-189b36a1cd8c",
                    "_return": True,
                    "groupId": "sg-04d018d184a18f647",
                },
                "requestID": "594fe3e3-0f74-4085-9336-189b36a1cd8c",
                "eventID": "52601748-2659-4ed8-b5fd-c530547b07ec",
                "eventType": "AwsApiCall",
                "recipientAccountId": "112233445566",
            },
        ),
        RuleTest(
            name="Terraform Security Group Authorize Egress",
            expected_result=False,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AROAIZCYMDBM4SJU65M54:ryan@example.com",
                    "arn": "arn:aws:sts::112233445566:assumed-role/ContinousDeployment/ryan@example.com",
                    "accountId": "112233445566",
                    "accessKeyId": "ASIAWDWBPTM3RJH7XXXX",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "AROAIZCYMDBM4SJU65M54",
                            "arn": "arn:aws:iam::112233445566:role/Operator",
                            "accountId": "112233445566",
                            "userName": "Operator",
                        },
                        "webIdFederationData": {},
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2020-04-30T23:50:12Z"},
                    },
                },
                "eventTime": "2020-04-30T23:51:08Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "AuthorizeSecurityGroupEgress",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "100.1.114.142",
                "userAgent": "aws-sdk-go/1.29.7 (go1.13.7; darwin; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.12.24 (+https://www.terraform.io)",
                "requestParameters": {
                    "groupId": "sg-03eee825d6bb78f54",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipProtocol": "-1",
                                "groups": {},
                                "ipRanges": {
                                    "items": [
                                        {
                                            "cidrIp": "0.0.0.0/0",
                                            "description": "Allow egress to the internet. Required for now until we land ECS/ECR endpoints in the VPC",
                                        },
                                    ],
                                },
                                "ipv6Ranges": {},
                                "prefixListIds": {},
                            },
                        ],
                    },
                },
                "responseElements": {"requestId": "4c7a5036-09d3-46e8-b0b6-f611ff1959a6", "_return": True},
                "requestID": "4c7a5036-09d3-46e8-b0b6-f611ff1959a6",
                "eventID": "1a593035-e072-49c4-8c72-4ff35e195330",
                "eventType": "AwsApiCall",
                "recipientAccountId": "112233445566",
            },
        ),
        RuleTest(
            name="Go Script Authorize Ingress",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": "AROAIZCYMDBM4SJU65M54:ryan@example.com",
                    "arn": "arn:aws:sts::112233445566:assumed-role/Operator/ryan@example.com",
                    "accountId": "112233445566",
                    "accessKeyId": "ASIAWDWBPTM3QPXQXXXX",
                    "sessionContext": {
                        "sessionIssuer": {
                            "type": "Role",
                            "principalId": "AROAIZCYMDBM4SJU65M54",
                            "arn": "arn:aws:iam::112233445566:role/Operator",
                            "accountId": "112233445566",
                            "userName": "Operator",
                        },
                        "webIdFederationData": {},
                        "attributes": {"mfaAuthenticated": "false", "creationDate": "2020-04-30T04:37:13Z"},
                    },
                },
                "eventTime": "2020-04-30T04:40:52Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "AuthorizeSecurityGroupIngress",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "100.1.114.142",
                "userAgent": "aws-sdk-go/1.24.1 (go1.14; darwin; amd64)",
                "requestParameters": {
                    "groupId": "sg-0d921df5d84f7270a",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipProtocol": "tcp",
                                "fromPort": 22,
                                "toPort": 22,
                                "groups": {},
                                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                                "ipv6Ranges": {},
                                "prefixListIds": {},
                            },
                        ],
                    },
                },
                "responseElements": {"requestId": "2be70b99-4937-4a76-b7d9-390b6d0eda73", "_return": True},
                "requestID": "2be70b99-4937-4a76-b7d9-390b6d0eda73",
                "eventID": "42155429-7e8e-43b5-9b5e-6953f80d51d5",
                "eventType": "AwsApiCall",
                "recipientAccountId": "112233445566",
            },
        ),
        RuleTest(
            name="AWS Console - Ingress SG Authorization Error",
            expected_result=False,
            log={
                "awsRegion": "us-west-2",
                "errorCode": "UnauthorizedOperation",
                "eventID": "504b492f-7832-406b-a4fd-45a13e48adc4",
                "eventName": "AuthorizeSecurityGroupIngress",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": "2021-01-24 04:55:45.000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": False,
                "recipientAccountId": "112233445566",
                "requestID": "91f34d65-513d-4e9f-a3de-e8d27f7ee4b2",
                "requestParameters": {
                    "groupId": "sg-04f0b44316f7d2471",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/16"}]},
                                "prefixListIds": {},
                                "fromPort": "443",
                                "toPort": "443",
                                "groups": {},
                                "ipProtocol": "tcp",
                                "ipv6Ranges": {},
                            },
                        ],
                    },
                },
                "responseElements": {"_return": True, "requestId": "91f34d65-513d-4e9f-a3de-e8d27f7ee4b2"},
                "sourceIPAddress": "136.25.37.134",
                "userAgent": "console.ec2.amazonaws.com",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalid": "ARORJ4ULULLE0EEJAAKDO:alan",
                    "arn": "arn:aws:sts::112233445566:assumed-role/TestAdmin/alan",
                    "accountid": "112233445566",
                    "accesskeyid": "ASIASWJRT64Z7ZLFLJNI",
                    "sessioncontext": {
                        "attributes": {"mfaauthenticated": "true", "creationdate": "2021-01-24T04:55:10Z"},
                        "sessionissuer": {
                            "type": "Role",
                            "principalid": "ARORJ4ULULLE0EEJAAKDO",
                            "arn": "arn:aws:iam::112233445566:role/TestAdmin",
                            "accountid": "112233445566",
                            "username": "TestAdmin",
                        },
                    },
                },
                "p_event_time": "2021-01-24 04:55:45.000",
                "p_parse_time": "2021-01-24 05:02:58.358",
                "p_log_type": "AWS.CloudTrail",
                "p_row_id": "1a57ff7ade26aaf5a1a4d7d20775",
                "p_source_id": "e55677c6-7ef5-4541-a443-0d0f17eec19f",
                "p_source_label": "CloudTrail Test",
                "p_any_ip_addresses": ["136.25.37.134"],
                "p_any_aws_account_ids": ["112233445566"],
                "p_any_aws_arns": [
                    "arn:aws:iam::112233445566:role/TestAdmin",
                    " arn:aws:sts::112233445566:assumed-role/TestAdmin/alan",
                ],
            },
        ),
    ]
