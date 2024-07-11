from pypanther import PantherLogType, PantherRule, PantherSeverity


class DupRuleB(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "DupRuleB"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
