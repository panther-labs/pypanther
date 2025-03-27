import unittest
from unittest import TestCase

import pytest

from pypanther.get import apply_overrides, get_panther_rules, get_rules


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

        r = get_rules(module=no_rules)
        assert len(r) == 0

    def test_rules(self) -> None:
        from .fixtures.get_rules_test_data import rules

        r = get_rules(module=rules)
        assert len(r) == 4

    def test_no_a_module(self) -> None:
        with pytest.raises(TypeError):
            get_rules(module="str")

    def test_imported_rule(self) -> None:
        import tests.fixtures.get_rules_test_data.imported_rules as imported_rules_module

        r = get_rules(module=imported_rules_module)
        assert len(r) == 1  # Should only include rules defined in this module
        # Verify the rule is the one defined in the module, not the imported one
        assert r[0].__module__ == "tests.fixtures.get_rules_test_data.imported_rules.imported_rules"
        assert r[0].id == "IMPORTED_RULE"


class TestApplyOverridesFromModule(unittest.TestCase):
    def test_no_overrides(self) -> None:
        from .fixtures.get_rules_test_data import no_rules

        r = apply_overrides(module=no_rules)

        assert len(r) == 0

    def test_overrides(self) -> None:
        from .fixtures.get_rules_test_data import rules

        r = apply_overrides(module=rules)
        assert len(r) == 3

    def test_no_a_module(self) -> None:
        with pytest.raises(TypeError):
            apply_overrides(module="str")


if __name__ == "__main__":
    unittest.main()
