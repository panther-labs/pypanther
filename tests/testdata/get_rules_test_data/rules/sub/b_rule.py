from pypanther import PantherLogType, PantherRule, PantherSeverity


class BRule(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "BRule"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
