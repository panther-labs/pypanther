from pypanther import PantherLogType, PantherRule, PantherSeverity


class DupRuleA(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "DupRuleA"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
