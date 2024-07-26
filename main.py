from pypanther import register, RuleTest, Rule, RuleMock, LogType, Severity


OUTSIDE = "outside"
def outside():
    return OUTSIDE

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
    
class OutsideMockTest(Rule):
    id = "outside_mock_test"
    display_name = "Outside Mock Test"
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.INFO
    tests = [
                RuleTest(
            name="Mock outside new",
            expected_result=False,
            mocks=[
                RuleMock(
                    object_name="OUTSIDE",
                    new="inside"
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
        RuleTest(
            name="Mock outside return_value",
            expected_result=False,
            mocks=[
                RuleMock(
                    object_name="outside",
                    return_value="inside"
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
        RuleTest(
            name="Mock outside side_effect",
            expected_result=False,
            mocks=[
                RuleMock(
                    object_name="outside",
                    side_effect=lambda: "inside"
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
    ]
    def rule(self, event):
        return outside() == "outside"

register([MockTestRule, OutsideMockTest])