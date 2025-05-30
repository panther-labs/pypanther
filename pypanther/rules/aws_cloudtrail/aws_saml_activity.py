from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSSuspiciousSAMLActivity(Rule):
    default_description = (
        "Identifies when SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML."
    )
    display_name = "AWS SAML Activity"
    default_reference = (
        "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-managing-saml-idp-console.html"
    )
    default_severity = Severity.MEDIUM
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "AWS.Suspicious.SAML.Activity-prototype"
    SAML_ACTIONS = ["UpdateSAMLProvider", "CreateSAMLProvider", "DeleteSAMLProvider"]

    def rule(self, event):
        # Allow AWSSSO to manage
        if event.deep_get("userIdentity", "arn", default="").endswith(":assumed-role/AWSServiceRoleForSSO/AWS-SSO"):
            return False
        # Don't alert on errors such as EntityAlreadyExistsException and NoSuchEntity
        if event.get("errorCode"):
            return False
        return event.get("eventSource") == "iam.amazonaws.com" and event.get("eventName") in self.SAML_ACTIONS

    def title(self, event):
        return f"[{event.deep_get('userIdentity', 'arn')}] performed [{event.get('eventName')}] in account [{event.get('recipientAccountId')}]"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="CreateSAMLProvider",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventID": "EID12345",
                "eventName": "CreateSAMLProvider",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2021-10-14 21:25:20",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "recipientAccountId": "0123456789",
                "requestID": "ABC1234",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "cloudformation.amazonaws.com",
                "userIdentity": {
                    "accessKeyId": "ABCDEFGHIJK",
                    "accountId": "0123456789",
                    "arn": "arn:aws:sts::0123456789:assumed-role/role/account",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "0123456789:AWSCloudFormation",
                    "sessionContext": {
                        "attributes": {"creationDate": "2021-10-14T21:25:20Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "0123456789",
                            "arn": "arn:aws:iam::0123456789:role/ServiceRole",
                            "principalId": "ABCDEFGI0123",
                            "type": "Role",
                            "userName": "ServiceRole",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="DeleteSAMLProvider",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventID": "EID12345",
                "eventName": "DeleteSAMLProvider",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2021-10-14 21:25:20",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "recipientAccountId": "0123456789",
                "requestID": "ABC1234",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "cloudformation.amazonaws.com",
                "userIdentity": {
                    "accessKeyId": "ABCDEFGHIJK",
                    "accountId": "0123456789",
                    "arn": "arn:aws:sts::0123456789:assumed-role/role/account",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "0123456789:AWSCloudFormation",
                    "sessionContext": {
                        "attributes": {"creationDate": "2021-10-14T21:25:20Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "0123456789",
                            "arn": "arn:aws:iam::0123456789:role/ServiceRole",
                            "principalId": "ABCDEFGI0123",
                            "type": "Role",
                            "userName": "ServiceRole",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Non Target Event",
            expected_result=False,
            log={
                "awsRegion": "us-east-1",
                "eventID": "EID12345",
                "eventName": "ListAccessKeys",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2021-10-13 18:35:08",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "readOnly": True,
                "recipientAccountId": "0123456789",
                "requestID": "requestID12345",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "console.amazonaws.com",
                "userIdentity": {
                    "accessKeyId": "ABCDEFGHIJKLMNOP",
                    "accountId": "0123456789",
                    "arn": "arn:aws:iam::0123456789:user/bob",
                    "principalId": "ABCDEF012345",
                    "sessionContext": {
                        "attributes": {"creationDate": "2021-10-13T18:35:02Z", "mfaAuthenticated": "true"},
                        "sessionIssuer": {},
                        "webIdFederationData": {},
                    },
                    "type": "IAMUser",
                    "userName": "bob",
                },
            },
        ),
        RuleTest(
            name="UpdateSAMLProvider",
            expected_result=True,
            log={
                "awsRegion": "us-east-1",
                "eventID": "EID12345",
                "eventName": "UpdateSAMLProvider",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2021-10-14 21:25:20",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "recipientAccountId": "0123456789",
                "requestID": "ABC1234",
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "cloudformation.amazonaws.com",
                "userIdentity": {
                    "accessKeyId": "ABCDEFGHIJK",
                    "accountId": "0123456789",
                    "arn": "arn:aws:sts::0123456789:assumed-role/role/account",
                    "invokedBy": "cloudformation.amazonaws.com",
                    "principalId": "0123456789:AWSCloudFormation",
                    "sessionContext": {
                        "attributes": {"creationDate": "2021-10-14T21:25:20Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "0123456789",
                            "arn": "arn:aws:iam::0123456789:role/ServiceRole",
                            "principalId": "ABCDEFGI0123",
                            "type": "Role",
                            "userName": "ServiceRole",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
        RuleTest(
            name="Activity from AWSSSO Service Managed Role",
            expected_result=False,
            log={
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventName": "CreateSAMLProvider",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2022-12-12 21:46:17.000000000",
                "eventType": "AwsApiCall",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_alert_context": {
                    "awsRegion": "us-east-1",
                    "eventName": "CreateSAMLProvider",
                    "eventSource": "iam.amazonaws.com",
                    "recipientAccountId": "123412341234",
                    "sourceIPAddress": "sso.amazonaws.com",
                    "userAgent": "sso.amazonaws.com",
                    "userIdentity": {
                        "accessKeyId": "ASIAXXXXNLMHSP3MFXX",
                        "accountId": "123412341234",
                        "arn": "arn:aws:sts::123412341234:assumed-role/AWSServiceRoleForSSO/AWS-SSO",
                        "invokedBy": "sso.amazonaws.com",
                        "principalId": "AROAT7BCMNLMONMOFFFFF:AWS-SSO",
                        "sessionContext": {
                            "attributes": {"creationDate": "2022-12-12T21:46:16Z", "mfaAuthenticated": "false"},
                            "sessionIssuer": {
                                "accountId": "123412341234",
                                "arn": "arn:aws:iam::123412341234:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO",
                                "principalId": "AROAT7BCMNLMONMOFFFFF",
                                "type": "Role",
                                "userName": "AWSServiceRoleForSSO",
                            },
                            "webIdFederationData": {},
                        },
                        "type": "AssumedRole",
                    },
                },
                "p_alert_creation_time": "2022-12-12 21:51:37.115853000",
                "p_alert_update_time": "2022-12-12 21:51:37.115853000",
                "p_any_aws_account_ids": ["123412341234"],
                "p_any_aws_arns": [
                    "arn:aws:iam::123412341234:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO",
                    "arn:aws:iam::123412341234:saml-provider/AWSSSO_abdf34fd171b4a7e_DO_NOT_DELETE",
                    "arn:aws:sts::123412341234:assumed-role/AWSServiceRoleForSSO/AWS-SSO",
                ],
                "p_any_domain_names": ["sso.amazonaws.com"],
                "p_any_trace_ids": ["ASIAXXXXNLMHSP3MFXX"],
                "p_any_usernames": ["AWSServiceRoleForSSO"],
                "p_event_time": "2022-12-12 21:46:17.000000000",
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2022-12-12 21:49:13.694384486",
                "p_rule_id": "AWS.Suspicious.SAML.Activity",
                "p_source_label": "YourOrg - Cloudtrail - Label",
                "readOnly": False,
                "recipientAccountId": "123412341234",
                "requestID": "cb89df1f-6019-427f-9a69-00b8b904ce0d",
                "requestParameters": {
                    "name": "AWSSSO_abdf34fd171b4a7e_DO_NOT_DELETE",
                    "sAMLMetadataDocument": '<?xml version="1.0" encoding="UTF-8"?></xml>',
                },
                "responseElements": {
                    "sAMLProviderArn": "arn:aws:iam::123412341234:saml-provider/AWSSSO_abdf34fd171b4a7e_DO_NOT_DELETE",
                },
                "sourceIPAddress": "sso.amazonaws.com",
                "userAgent": "sso.amazonaws.com",
                "userIdentity": {
                    "accessKeyId": "ASIAXXXXNLMHSP3MFXX",
                    "accountId": "123412341234",
                    "arn": "arn:aws:sts::123412341234:assumed-role/AWSServiceRoleForSSO/AWS-SSO",
                    "invokedBy": "sso.amazonaws.com",
                    "principalId": "AROAT7BCMNLMONMOFFFFF:AWS-SSO",
                    "sessionContext": {
                        "attributes": {"creationDate": "2022-12-12T21:46:16Z", "mfaAuthenticated": "false"},
                        "sessionIssuer": {
                            "accountId": "123412341234",
                            "arn": "arn:aws:iam::123412341234:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO",
                            "principalId": "AROAT7BCMNLMONMOFFFFF",
                            "type": "Role",
                            "userName": "AWSServiceRoleForSSO",
                        },
                        "webIdFederationData": {},
                    },
                    "type": "AssumedRole",
                },
            },
        ),
    ]
