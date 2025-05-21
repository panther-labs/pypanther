import json

from panther_detection_helpers.caching import add_to_string_set

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSSecretsManagerRetrieveSecretsMultiRegion(Rule):
    id = "AWS.SecretsManager.RetrieveSecretsMultiRegion-prototype"
    display_name = "AWS Secrets Manager Retrieve Secrets Multi-Region"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Credential Access", "Stratus Red Team", "Beta"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    default_severity = Severity.INFO
    default_description = "An attacker attempted to retrieve a high number of Secrets Manager secrets by batch, through secretsmanager:BatchGetSecretValue (released Novemeber 2023).  An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets. This rule identifies BatchGetSecretValue events for multiple regions in a short period of time.\n"
    default_runbook = "https://aws.amazon.com/blogs/security/how-to-use-the-batchgetsecretsvalue-api-to-improve-your-client-side-applications-with-aws-secrets-manager/"
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.secretsmanager-batch-retrieve-secrets/"
    dedup_period_minutes = 1440
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]
    RULE_ID = "AWS.SecretsManager.RetrieveSecretsMultiRegion"
    UNIQUE_REGION_THRESHOLD = 5
    WITHIN_TIMEFRAME_MINUTES = 10

    def rule(self, event):
        if event.get("eventName") != "BatchGetSecretValue":
            return False
        user = event.udm("actor_user")
        key = f"{self.RULE_ID}-{user}"
        unique_regions = add_to_string_set(key, event.get("awsRegion"), self.WITHIN_TIMEFRAME_MINUTES * 60)
        if isinstance(unique_regions, str):
            unique_regions = json.loads(unique_regions)
        if len(unique_regions) >= self.UNIQUE_REGION_THRESHOLD:
            return True
        return False

    def title(self, event):
        user = event.udm("actor_user")
        return f"[{user}] attempted to retrieve secrets from AWS Secrets Manager in multiple regions"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="BatchGetSecretValue Catch-All",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="add_to_string_set",
                    return_value='["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]',
                ),
            ],
            log={
                "eventSource": "secretsmanager.amazonaws.com",
                "eventName": "BatchGetSecretValue",
                "requestParameters": {"filters": [{"key": "tag-key", "values": ["!tagKeyThatWillNeverExist"]}]},
                "responseElements": None,
                "readOnly": True,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "012345678901",
            },
        ),
    ]
