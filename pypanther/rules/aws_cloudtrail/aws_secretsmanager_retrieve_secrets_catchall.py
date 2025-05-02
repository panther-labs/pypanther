from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSSecretsManagerBatchRetrieveSecretsCatchAll(Rule):
    id = "AWS.SecretsManager.BatchRetrieveSecretsCatchAll-prototype"
    display_name = "AWS Secrets Manager Batch Retrieve Secrets Catch-All"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Credential Access", "Stratus Red Team", "Beta"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    default_severity = Severity.INFO
    default_description = "An attacker attempted to retrieve a high number of Secrets Manager secrets by batch, through secretsmanager:BatchGetSecretValue (released Novemeber 2023).  An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets. Although BatchGetSecretValue requires a list of secret IDs or a filter, an attacker may use a catch-all filter to retrieve all secrets by batch. This rule identifies BatchGetSecretValue events with a catch-all filter.\n"
    default_runbook = "https://aws.amazon.com/blogs/security/how-to-use-the-batchgetsecretsvalue-api-to-improve-your-client-side-applications-with-aws-secrets-manager/"
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.secretsmanager-batch-retrieve-secrets/"
    dedup_period_minutes = 1440
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        if event.get("eventName") != "BatchGetSecretValue":
            return False
        filters = event.deep_get("requestParameters", "filters", default=[])
        for filt in filters:
            if filt.get("key") != "tag-key":
                return False
            if any(not value.startswith("!") for value in filt.get("values")):
                return False
        return True

    def title(self, event):
        user = event.udm("actor_user")
        return f"[{user}] attempted to batch retrieve secrets from AWS Secrets Manager with a catch-all filter"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="BatchGetSecretValue Catch-All",
            expected_result=True,
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
        RuleTest(
            name="BatchGetSecretValue Catch-All with other filters",
            expected_result=False,
            log={
                "eventSource": "secretsmanager.amazonaws.com",
                "eventName": "BatchGetSecretValue",
                "requestParameters": {
                    "filters": [
                        {"key": "tag-key", "values": ["!tagKeyThatWillNeverExist"]},
                        {"key": "tag-key", "values": ["tagThatExists"]},
                    ],
                },
                "responseElements": None,
                "readOnly": True,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "012345678901",
            },
        ),
    ]
