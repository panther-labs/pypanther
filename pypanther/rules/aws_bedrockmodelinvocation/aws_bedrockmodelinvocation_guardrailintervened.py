from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class AWSBedrockModelInvocationGuardRailIntervened(Rule):
    id = "AWS.BedrockModelInvocation.GuardRailIntervened-prototype"
    display_name = "AWS Bedrock Model Invocation GuardRail Intervened"
    log_types = [LogType.AWS_BEDROCK_MODEL_INVOCATION]
    tags = ["AWS", "Bedrock", "Beta", "Persistence", "Manipulate AI Model"]
    default_severity = Severity.INFO
    reports = {"MITRE ATT&CK": ["TA0006:T0018.000"]}
    default_description = "Detects when AWS Bedrock guardrail features have intervened during AI model invocations. It specifically monitors when an AI model request was blocked by Guardrails. This helps security teams identify when users attempt to generate potentially harmful or inappropriate content through AWS Bedrock models."
    default_runbook = "Confirm alert details by reviewing the model ID, operation name, account ID, and the specific guardrail intervention reasons provided in the alert description. Analyze the user prompts that triggered the guardrail by examining the Bedrock console logs for the associated requestId, looking for patterns of attempted model poisoning or prompt injection techniques. If suspicious activity is confirmed, temporarily restrict the access of the malicious actor to Bedrock services, preserve all evidence of the interaction, and escalate to the security team for further analysis of potential AI model manipulation attempts. https://atlas.mitre.org/mitigations/AML.M0005"
    default_reference = "https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.bedrock-invoke-model/, https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html"
    summary_attributes = ["p_any_aws_account_ids", "p_any_aws_arns"]
    inline_filters = [{"All": []}]

    def rule(self, event):
        if event.get("operation") != "InvokeModel" and event.get("operation") != "Converse":
            return False
        stop_reason = event.deep_get("output", "outputBodyJSON", "stopReason", default="<UNKNOWN REASON>")
        action_reason = event.deep_get(
            "output",
            "outputBodyJSON",
            "amazon-bedrock-trace",
            "guardrail",
            "actionReason",
            default="<UNKNOWN ACTION REASON>",
        )
        return stop_reason == "guardrail_intervened" or action_reason.startswith("Guardrail blocked")

    def title(self, event):
        model_id = event.get("modelId")
        operation_name = event.get("operation")
        account_id = event.get("accountId")
        stop_reason = event.deep_get("output", "outputBodyJSON", "stopReason", default="<UNKNOWN REASON>")
        action_reason = event.deep_get(
            "output",
            "outputBodyJSON",
            "amazon-bedrock-trace",
            "guardrail",
            "actionReason",
            default="<UNKNOWN ACTION REASON>",
        )
        if action_reason == "<UNKNOWN ACTION REASON>":
            return f"The model [{model_id}] was invoked with the operation [{operation_name}] by the account [{account_id}]. Stop reason [{stop_reason}]."
        if stop_reason == "<UNKNOWN REASON>":
            return f"The model [{model_id}] was invoked with the operation [{operation_name}] by the account [{account_id}]. Action reason [{action_reason}]."
        # Handle the case when both values are known
        return f"The model [{model_id}] was invoked with the operation [{operation_name}] by the account [{account_id}]. Stop reason [{stop_reason}]. Action reason [{action_reason}]."

    tests = [
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
            name="Regular Converse Operation",
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
        RuleTest(
            name="Suspicious Converse Operation",
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
                        "stopReason": "guardrail_intervened",
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
            name="Suspicious Invoke Operation",
            expected_result=True,
            log={
                "accountId": "111111111111",
                "identity": {"arn": "arn:aws:sts::111111111111:assumed-role/role_details/suspicious.user"},
                "input": {
                    "inputBodyJson": {
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 100,
                        "messages": [{"content": "I have a very suspicious question.", "role": "user"}],
                        "system": "You are a helpful assistant.",
                    },
                    "inputContentType": "application/json",
                },
                "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
                "operation": "InvokeModel",
                "output": {
                    "outputBodyJson": {
                        "amazon-bedrock-guardrailAction": "INTERVENED",
                        "amazon-bedrock-trace": {
                            "guardrail": {
                                "actionReason": "Guardrail blocked.",
                                "input": {
                                    "h28wrktbwagn": {
                                        "contentPolicy": {
                                            "filters": [
                                                {
                                                    "action": "BLOCKED",
                                                    "confidence": "HIGH",
                                                    "detected": True,
                                                    "filterStrength": "HIGH",
                                                    "type": "VIOLENCE",
                                                },
                                            ],
                                        },
                                        "invocationMetrics": {
                                            "guardrailCoverage": {"textCharacters": {"guarded": 62, "total": 62}},
                                            "guardrailProcessingLatency": 179,
                                            "usage": {
                                                "contentPolicyImageUnits": 0,
                                                "contentPolicyUnits": 1,
                                                "contextualGroundingPolicyUnits": 0,
                                                "sensitiveInformationPolicyFreeUnits": 0,
                                                "sensitiveInformationPolicyUnits": 0,
                                                "topicPolicyUnits": 0,
                                                "wordPolicyUnits": 0,
                                            },
                                        },
                                    },
                                },
                            },
                        },
                        "content": [{"text": "You shouldn't ask this question", "type": "text"}],
                        "role": "assistant",
                        "type": "message",
                    },
                    "outputContentType": "application/json",
                },
                "region": "us-west-2",
                "requestId": "ba78ac1f-5ea4-4e2a-a936-92f7e13c96c4",
                "schemaType": "ModelInvocationLog",
                "schemaVersion": "1.0",
                "timestamp": "2025-05-15 14:14:49.000000000",
            },
        ),
    ]
