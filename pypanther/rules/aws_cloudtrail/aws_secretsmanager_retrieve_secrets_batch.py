from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_rule_context


@panther_managed
class AWSSecretsManagerBatchRetrieveSecrets(Rule):
    id = "AWS.SecretsManager.BatchRetrieveSecrets-prototype"
    display_name = "AWS Secrets Manager Batch Retrieve Secrets"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Credential Access", "Stratus Red Team", "Beta"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    default_severity = Severity.INFO
    default_description = "An attacker attempted to retrieve a high number of Secrets Manager secrets by batch, through secretsmanager:BatchGetSecretValue (released Novemeber 2023).  An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets.\n"
    default_runbook = "https://aws.amazon.com/blogs/security/how-to-use-the-batchgetsecretsvalue-api-to-improve-your-client-side-applications-with-aws-secrets-manager/"
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.secretsmanager-batch-retrieve-secrets/"
    threshold = 5
    dedup_period_minutes = 1440
    summary_attributes = ["eventName", "userAgent", "sourceIpAddress", "recipientAccountId", "p_any_aws_arns"]

    def rule(self, event):
        if event.get("eventName") == "BatchGetSecretValue":
            return True
        return False

    def title(self, event):
        user = event.udm("actor_user")
        return f"[{user}] attempted to batch retrieve a large number of secrets from AWS Secrets Manager"

    def alert_context(self, event):
        return aws_rule_context(event)

    tests = [
        RuleTest(
            name="BatchGetSecretValue",
            expected_result=True,
            log={
                "eventSource": "secretsmanager.amazonaws.com",
                "eventName": "BatchGetSecretValue",
                "requestParameters": {"filters": [{"key": "tag-key", "values": ["StratusRedTeam"]}]},
                "responseElements": None,
                "readOnly": True,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "012345678901",
            },
        ),
    ]
