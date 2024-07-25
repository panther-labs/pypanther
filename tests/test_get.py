import unittest
from unittest import TestCase

import pytest

from pypanther.get import get_panther_rules, get_rules_from_module


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


class TestGetRulesFromModule(unittest.TestCase):
    def test_no_rules(self) -> None:
        from .fixtures.get_rules_test_data import no_rules

        r = get_rules_from_module(module=no_rules)
        assert len(r) == 0

    def test_rules(self) -> None:
        from .fixtures.get_rules_test_data import rules

        r = get_rules_from_module(module=rules)
        assert len(r) == 4

    def test_no_a_module(self) -> None:
        with pytest.raises(TypeError):
            get_rules_from_module(module="str")


if __name__ == "__main__":
    unittest.main()
