import unittest

from prettytable import PrettyTable

from pypanther.base import PantherRule
from pypanther.get import table_print


class TestEDRRule(PantherRule):
    RuleID = "EDR"
    LogTypes = ["CrowdStrike", "SentinelOne", "AWS"]
    DisplayName = "EDR Rule"
    Severity = "High"
    Enabled = True
    CreateAlert = False

    def rule(self, event):
        return True


class TestPaloAltoRule(PantherRule):
    RuleID = "Firewall"
    LogTypes = ["PaloAlto"]
    DisplayName = "Firewall Rule"
    Severity = "Medium"
    Enabled = True
    CreateAlert = True

    def rule(self, event):
        return True


class TestTablePrint(unittest.TestCase):
    def test_table_print(self):
        rules = [TestEDRRule, TestPaloAltoRule]
        output = table_print(rules)

        expected_table = PrettyTable()
        expected_table.field_names = [
            "RuleID",
            "LogTypes",
            "DisplayName",
            "Severity",
            "Enabled",
            "CreateAlert",
        ]
        expected_table.add_row(
            ["EDR", "CrowdStrike, SentinelOne, +1", "EDR Rule", "High", "True", "False"]
        )
        expected_table.add_row(["Firewall", "PaloAlto", "Firewall Rule", "Medium", "True", "True"])

        self.assertEqual(str(output), str(expected_table))


if __name__ == "__main__":
    unittest.main()
