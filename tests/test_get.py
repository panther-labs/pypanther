import textwrap
import unittest
from typing import Type

import pytest

from pypanther.base import PantherRule
from pypanther.get import print_rule_table


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


def test_print_rule_table(capsys):
    rules: list[Type[PantherRule]] = [TestEDRRule, TestPaloAltoRule]
    print_rule_table(rules)
    std = capsys.readouterr()

    pytest.maxDiff = None
    exp = textwrap.dedent(
        """
        +----------+------------------------------+---------------+----------+---------+-------------+
        |  RuleID  |           LogTypes           |  DisplayName  | Severity | Enabled | CreateAlert |
        +----------+------------------------------+---------------+----------+---------+-------------+
        |   EDR    | CrowdStrike, SentinelOne, +1 |    EDR Rule   |   High   |   True  |    False    |
        | Firewall |           PaloAlto           | Firewall Rule |  Medium  |   True  |     True    |
        +----------+------------------------------+---------------+----------+---------+-------------+
    """
    ).lstrip()
    assert std.out == exp
    assert std.err == ""


if __name__ == "__main__":
    unittest.main()
