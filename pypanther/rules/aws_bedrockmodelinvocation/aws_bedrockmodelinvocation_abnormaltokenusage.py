from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AWSBedrockModelInvocationAbnormalTokenUsage(Rule):
    id = "AWS.BedrockModelInvocation.AbnormalTokenUsage-prototype"
    display_name = "AWS Bedrock Model Invocation Abnormal Token Usage"
    log_types = [LogType.AWS_BEDROCK_MODEL_INVOCATION]
    tags = ["AWS", "Bedrock", "Beta", "Resource Hijacking"]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0040:T1496.004"]}
    default_description = "Monitors for potential misuse or abuse of AWS Bedrock AI models by detecting abnormal token usage patterns and alerts when the total token usage exceeds the appropriate threshold for each different type of model."
    default_runbook = "Verify the alert details by checking token usage, model ID, and account information to confirm unusual activity, examine user access patterns to identify potential credential compromise, and look for evidence of prompt injection, unusual repetition, or attempts to bypass usage limits. Apply stricter usage quotas to the affected account, block suspicious IP addresses, and enhance the guardrails that are in place."
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.bedrock-invoke-model/"
    summary_attributes = ["p_any_aws_account_ids", "p_any_aws_arns"]
    inline_filters = [{"All": []}]

    def rule(self, event):
        # Only process InvokeModel and Converse operations
        if event.get("operation") not in ["InvokeModel", "Converse"]:
            return False
        # retrieve the necessary values from the logs
        token_usage = event.deep_get("output", "outputBodyJson", "usage", "totalTokens", default=0)
        model_id = event.get("modelId", default="")
        # Get the appropriate threshold for each model
        if "haiku" in model_id:
            threshold = 3000
        elif "sonnet" in model_id:
            threshold = 4000
        elif "opus" in model_id:
            threshold = 5000
        else:
            threshold = 4000  # default threshold
        # Check for abnormal token usage
        if token_usage > threshold:
            return True
        # Flag unusual token patterns (high usage with no actual output)
        output_tokens = event.deep_get("output", "outputBodyJson", "usage", "outputTokens", default=0)
        if token_usage > 1000 and output_tokens == 0:
            return True
        return False

    def title(self, event):
        model_id = event.get("modelId", default="unknown")
        operation_name = event.get("operation", default="unknown")
        account_id = event.get("accountId", default="unknown")
        token_usage = event.deep_get("output", "outputBodyJson", "usage", "totalTokens", default=0)
        title_parts = [
            f"Abnormal token usage detected: {token_usage} tokens",
            f"Model: {model_id}",
            f"Operation: {operation_name}",
            f"Account: {account_id}",
        ]
        return " | ".join(title_parts)

    tests = [
        RuleTest(
            name="Converse Operation Unusual Token Patterns",
            expected_result=True,
            log={
                "accountId": "111111111111",
                "identity": {"arn": "arn:aws:sts::111111111111:assumed-role/role_details/suspicious.user"},
                "input": {
                    "inputBodyJson": {
                        "messages": [{"content": [{"text": "I have a very suspicious question."}], "role": "user"}],
                    },
                    "inputContentType": "application/json",
                    "inputTokenCount": 0,
                },
                "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
                "operation": "Converse",
                "output": {
                    "outputBodyJson": {
                        "metrics": {"latencyMs": 249},
                        "output": {
                            "message": {"content": [{"text": "You shouldn't ask this question"}], "role": "assistant"},
                        },
                        "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 2000},
                    },
                    "outputContentType": "application/json",
                    "outputTokenCount": 0,
                },
                "region": "us-west-2",
                "requestId": "bb98d9a8-bd9a-47ca-976b-f165ef1f8b67",
                "schemaType": "ModelInvocationLog",
                "schemaVersion": "1.0",
                "timestamp": "2025-05-15 14:17:22.000000000",
            },
        ),
        RuleTest(
            name="Converse Operation with Abnormal Token Usage",
            expected_result=True,
            log={
                "accountId": "111111111111",
                "identity": {"arn": "arn:aws:sts::111111111111:assumed-role/role_details/suspicious.user"},
                "input": {
                    "inputBodyJson": {
                        "messages": [{"content": [{"text": "I have a very suspicious question."}], "role": "user"}],
                    },
                    "inputContentType": "application/json",
                    "inputTokenCount": 0,
                },
                "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
                "operation": "Converse",
                "output": {
                    "outputBodyJson": {
                        "metrics": {"latencyMs": 249},
                        "output": {
                            "message": {"content": [{"text": "You shouldn't ask this question"}], "role": "assistant"},
                        },
                        "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 5000},
                    },
                    "outputContentType": "application/json",
                    "outputTokenCount": 0,
                },
                "region": "us-west-2",
                "requestId": "bb98d9a8-bd9a-47ca-976b-f165ef1f8b67",
                "schemaType": "ModelInvocationLog",
                "schemaVersion": "1.0",
                "timestamp": "2025-05-15 14:17:22.000000000",
            },
        ),
        RuleTest(
            name="Perform Another Operation",
            expected_result=False,
            log={
                "accountId": "111111111111",
                "identity": {"arn": "arn:aws:sts::111111111111:assumed-role/role_details/regular.user"},
                "input": {
                    "inputBodyJson": {
                        "messages": [{"content": [{"text": "I have a rather normal question."}], "role": "user"}],
                    },
                    "inputContentType": "application/json",
                    "inputTokenCount": 0,
                },
                "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
                "operation": "ListModels",
                "output": {
                    "outputBodyJson": {
                        "metrics": {"latencyMs": 249},
                        "output": {
                            "message": {"content": [{"text": "I can respond to this question"}], "role": "assistant"},
                        },
                        "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0},
                    },
                    "outputContentType": "application/json",
                    "outputTokenCount": 0,
                },
                "region": "us-west-2",
                "requestId": "bb98d9a8-bd9a-47ca-976b-f165ef1f8b67",
                "schemaType": "ModelInvocationLog",
                "schemaVersion": "1.0",
                "timestamp": "2025-05-15 14:17:22.000000000",
            },
        ),
        RuleTest(
            name="Regular Converse Operation with Normal Token Usage",
            expected_result=False,
            log={
                "accountId": "111111111111",
                "identity": {"arn": "arn:aws:sts::111111111111:assumed-role/role_details/regular.user"},
                "input": {
                    "inputBodyJson": {
                        "messages": [{"content": [{"text": "I have a rather normal question."}], "role": "user"}],
                    },
                    "inputContentType": "application/json",
                    "inputTokenCount": 0,
                },
                "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
                "operation": "Converse",
                "output": {
                    "outputBodyJson": {
                        "metrics": {"latencyMs": 249},
                        "output": {
                            "message": {"content": [{"text": "I can respond to this question"}], "role": "assistant"},
                        },
                        "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0},
                    },
                    "outputContentType": "application/json",
                    "outputTokenCount": 0,
                },
                "region": "us-west-2",
                "requestId": "bb98d9a8-bd9a-47ca-976b-f165ef1f8b67",
                "schemaType": "ModelInvocationLog",
                "schemaVersion": "1.0",
                "timestamp": "2025-05-15 14:17:22.000000000",
            },
        ),
    ]
