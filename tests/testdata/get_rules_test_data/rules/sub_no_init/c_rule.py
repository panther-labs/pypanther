from pypanther import PantherSeverity, PantherRule, PantherLogType


class CRule(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "CRule"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
