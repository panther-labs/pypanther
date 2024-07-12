from pypanther import PantherLogType, PantherRule, PantherSeverity


class CRule(PantherRule):
    default_severity = PantherSeverity.info
    id_ = "CRule"
    log_types = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
