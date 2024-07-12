from pypanther import PantherLogType, PantherRule, PantherSeverity


class BRule(PantherRule):
    default_severity = PantherSeverity.info
    id_ = "BRule"
    log_types = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
