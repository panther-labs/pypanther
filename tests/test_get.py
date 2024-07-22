import textwrap
import unittest

import pytest

from pypanther.base import Rule
from pypanther.get import get_rules, print_rule_table, get_panther_rules
from unittest import TestCase


class TestGetPantherRules(TestCase):
    def test_has_rules(self) -> None:
        assert len(get_panther_rules()) > 400

    def test_supported_args(self) -> None:
        # this just statically checks that all the args are still there
        # mostly just prevents breaking changes. no need to assert anything
        get_panther_rules(
            log_types=None,
            id=None,
            create_alert=None,
            dedup_period_minutes=None,
            display_name=None,
            enabled=None,
            scheduled_queries=None,
            summary_attributes=None,
            tests=None,
            threshold=None,
            tags=None,
            reports=None,
            default_severity=None,
            default_description=None,
            default_reference=None,
            default_runbook=None,
            default_destinations=None,
        )


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


class TestGetRules(unittest.TestCase):
    def test_no_rules(self) -> None:
        from .fixtures.get_rules_test_data import no_rules

        r = get_rules(module=no_rules)
        assert len(r) == 0

    def test_rules(self) -> None:
        from .fixtures.get_rules_test_data import rules

        r = get_rules(module=rules)
        assert len(r) == 4

    def test_no_a_module(self) -> None:
        with pytest.raises(TypeError):
            get_rules(module="str")


if __name__ == "__main__":
    unittest.main()
