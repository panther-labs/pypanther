from pypanther import register, RuleTest, Rule, RuleMock, LogType, Severity


class MockTestRule(Rule):
    id = "mock_test_rule"
    display_name = "Mock Test Rule"
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.INFO
    tests = [
        RuleTest(
            name="Mock new Test",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="VARIABLE",
                    new=["test"]
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
        RuleTest(
            name="Mock side_effect Test",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="rule",
                    side_effect=lambda e: e.get("action") == "Blocked"
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
        RuleTest(
            name="Mock return_value Test",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="rule",
                    return_value=True
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
    ]

    VARIABLE = []
    def rule(self, event):
        return self.VARIABLE != []

register(MockTestRule)