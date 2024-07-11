from pypanther import PantherSeverity, PantherRule, PantherLogType


class ARule(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "ARule"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
