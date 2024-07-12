from pypanther import PantherLogType, PantherRule, PantherSeverity


class ARule(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "ARule"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
