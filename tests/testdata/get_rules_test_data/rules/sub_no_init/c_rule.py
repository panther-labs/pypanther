from pypanther import PantherLogType, PantherRule, PantherSeverity


class CRule(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "CRule"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
