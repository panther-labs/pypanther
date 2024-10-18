from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AWSWAFDisassociation(Rule):
    default_description = "Detection to alert when a WAF disassociates from a source."
    display_name = "AWS WAF Disassociation"
    default_reference = "https://attack.mitre.org/techniques/T1078/"
    default_severity = Severity.CRITICAL
    reports = {"MITRE ATT&CK": ["TA0004:T1498"]}
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.WAF.Disassociation-prototype"

    def rule(self, event):
        return event.get("eventName") == "DisassociateWebACL"

    def title(self, event):
        return f"AWS Account ID [{event.get('recipientAccountId')}] disassociated WebACL [{event.deep_get('requestParameters', 'resourceArn')}]"

    def alert_context(self, event):
        return {
            "awsRegion": event.get("awsRegion"),
            "eventName": event.get("eventName"),
            "recipientAccountId": event.get("recipientAccountId"),
            "requestID": event.get("requestID"),
            "requestParameters": event.deep_get("requestParameters", "resourceArn"),
            "userIdentity": event.deep_get("userIdentity", "principalId"),
        }

    tests = [
        RuleTest(
            name="WAF-Disassociate",
            expected_result=True,
            log={
                "apiVersion": "2019-04-23",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "94678efc-2176-462c-b0c9-a612881a39ed",
                "eventName": "DisassociateWebACL",
                "eventSource": "wafv2.amazonaws.com",
                "eventTime": "2022-09-29 23:04:35",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["012345678910"],
                "p_any_aws_arns": [
                    "arn:aws:elasticloadbalancing:us-west-2:012345678910:loadbalancer/app/web/84dc5457e450dba5",
                    "arn:aws:iam::012345678910:role/DevAdministrator",
                    "arn:aws:sts::012345678910:assumed-role/DevAdministrator/example_user",
                ],
                "p_any_domain_names": ["AWS Internal"],
                "p_any_trace_ids": ["ASIARLIVEKVNJNSTUSF6"],
                "p_event_time": "2022-09-29 23:04:35",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-09-29 23:08:26.172",
                "p_row_id": "5ad3a83ca88f938cbff8fdd913d1ce1d",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "Panther Identity Org CloudTrail",
                "readOnly": False,
                "recipientAccountId": "012345678910",
                "requestID": "e4d47992-90f1-47f0-bff7-de18a8277005",
                "requestParameters": {
                    "resourceArn": "arn:aws:elasticloadbalancing:us-west-2:012345678910:loadbalancer/app/web/84dc5457e450dba5",
                },
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "AWS Internal",
                "userAgent": "AWS Internal",
                "userIdentity": {
                    "accessKeyId": "ASIARLIVEKVNJNSTUSF6",
                    "accountId": "012345678910",
                    "arn": "arn:aws:sts::012345678910:assumed-role/DevAdministrator/example_user",
                    "principalId": "AROARLIVEKVNIRVGDLJWJ:example_user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-09-29T22:51:13Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "012345678910",
                            "arn": "arn:aws:iam::012345678910:role/DevAdministrator",
                            "principalId": "AROARLIVEKVNIRVGDLJWJ",
                            "type": "Role",
                            "userName": "DevAdministrator",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="WAF - List WebACLs",
            expected_result=False,
            log={
                "apiVersion": "2019-04-23",
                "awsRegion": "us-west-2",
                "eventCategory": "Management",
                "eventID": "94678efc-2176-462c-b0c9-a612881a39ed",
                "eventName": "ListWebACLs",
                "eventSource": "wafv2.amazonaws.com",
                "eventTime": "2022-09-29 23:04:35",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_any_aws_account_ids": ["012345678910"],
                "p_any_aws_arns": [
                    "arn:aws:elasticloadbalancing:us-west-2:012345678910:loadbalancer/app/web/84dc5457e450dba5",
                    "arn:aws:iam::012345678910:role/DevAdministrator",
                    "arn:aws:sts::012345678910:assumed-role/DevAdministrator/example_user",
                ],
                "p_any_domain_names": ["AWS Internal"],
                "p_any_trace_ids": ["ASIARLIVEKVNJNSTUSF6"],
                "p_event_time": "2022-09-29 23:04:35",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-09-29 23:08:26.172",
                "p_row_id": "5ad3a83ca88f938cbff8fdd913d1ce1d",
                "p_source_id": "125a8146-e3ea-454b-aed7-9e08e735b670",
                "p_source_label": "Panther Identity Org CloudTrail",
                "readOnly": False,
                "recipientAccountId": "012345678910",
                "requestID": "e4d47992-90f1-47f0-bff7-de18a8277005",
                "requestParameters": {
                    "resourceArn": "arn:aws:elasticloadbalancing:us-west-2:012345678910:loadbalancer/app/web/84dc5457e450dba5",
                },
                "sessionCredentialFromConsole": True,
                "sourceIPAddress": "AWS Internal",
                "userAgent": "AWS Internal",
                "userIdentity": {
                    "accessKeyId": "ASIARLIVEKVNJNSTUSF6",
                    "accountId": "012345678910",
                    "arn": "arn:aws:sts::012345678910:assumed-role/DevAdministrator/example_user",
                    "principalId": "AROARLIVEKVNIRVGDLJWJ:example_user",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-09-29T22:51:13Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {
                            "accountId": "012345678910",
                            "arn": "arn:aws:iam::012345678910:role/DevAdministrator",
                            "principalId": "AROARLIVEKVNIRVGDLJWJ",
                            "type": "Role",
                            "userName": "DevAdministrator",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
