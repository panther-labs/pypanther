import json
import textwrap

import pytest

from pypanther.base import Rule
from pypanther.display import print_rule_table, print_rules_as_json


class TestEDRRule(Rule):
    id = "EDR"
    log_types = ["CrowdStrike", "SentinelOne", "AWS"]
    display_name = "EDR Rule"
    default_severity = "High"
    enabled = True
    create_alert = False

    def rule(self, event):
        return True


class TestPaloAltoRule(Rule):
    id = "Firewall"
    log_types = ["PaloAlto"]
    display_name = "Firewall Rule"
    default_severity = "Medium"
    enabled = True
    create_alert = True

    def rule(self, event):
        return True


def test_print_rule_table(capsys):
    rules = [TestEDRRule, TestPaloAltoRule]
    print_rule_table(rules)
    std = capsys.readouterr()

    pytest.maxDiff = None
    exp = textwrap.dedent(
        """
        +----------+------------------------------+------------------+---------+
        |    id    |          log_types           | default_severity | enabled |
        +----------+------------------------------+------------------+---------+
        |   EDR    | CrowdStrike, SentinelOne, +1 |       High       |   True  |
        | Firewall |           PaloAlto           |      Medium      |   True  |
        +----------+------------------------------+------------------+---------+
        Total rules: 2
    """,
    ).lstrip()

    assert std.out == exp
    assert std.err == ""


def test_print_rule_table_no_total(capsys):
    rules = [TestEDRRule, TestPaloAltoRule]
    print_rule_table(rules, print_total=False)
    std = capsys.readouterr()

    pytest.maxDiff = None
    exp = textwrap.dedent(
        """
        +----------+------------------------------+------------------+---------+
        |    id    |          log_types           | default_severity | enabled |
        +----------+------------------------------+------------------+---------+
        |   EDR    | CrowdStrike, SentinelOne, +1 |       High       |   True  |
        | Firewall |           PaloAlto           |      Medium      |   True  |
        +----------+------------------------------+------------------+---------+
    """,
    ).lstrip()

    assert std.out == exp
    assert std.err == ""


def test_print_rules_as_json(capsys):
    rules = [TestEDRRule, TestPaloAltoRule]
    print_rules_as_json(rules)
    std = capsys.readouterr()

    pytest.maxDiff = None
    exp = {
        "rules": [
            {
                "log_types": ["CrowdStrike", "SentinelOne", "AWS"],
                "id": "EDR",
                "default_severity": "High",
                "enabled": True,
            },
            {
                "log_types": ["PaloAlto"],
                "id": "Firewall",
                "default_severity": "Medium",
                "enabled": True,
            },
        ],
        "total_rules": 2,
    }

    assert json.loads(std.out) == exp
    assert std.err == ""
