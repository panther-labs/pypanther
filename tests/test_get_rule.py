import argparse
from typing import Type

import pytest

from pypanther.base import TYPE_RULE, Rule
from pypanther.get import get_panther_rules
from pypanther.get_rule import run


class TestRun:
    def test_not_found(self) -> None:
        rule_id = "Not.A.Real.ID"
        rc, err_msg = run(argparse.Namespace(id=rule_id, type=TYPE_RULE.lower(), output="text"))
        assert rc == 1
        assert rule_id in err_msg

    def test_invalid_output(self) -> None:
        rule_id = "GitHub.Team.Modified-prototype"
        fake_output = "fake_output"
        rc, err_msg = run(argparse.Namespace(id=rule_id, type=TYPE_RULE.lower(), output=fake_output))
        assert rc == 1
        assert fake_output in err_msg

    @pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
    def test_happy_path_text(self, rule: Type[Rule]) -> None:
        rc, err_msg = run(argparse.Namespace(id=rule.id, type=TYPE_RULE.lower(), output="text"))
        assert rc == 0
        assert err_msg == ""

    @pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
    def test_happy_path_json(self, rule: Type[Rule]) -> None:
        rc, err_msg = run(argparse.Namespace(id=rule.id, type=TYPE_RULE.lower(), output="json"))
        assert rc == 0
        assert err_msg == ""


if __name__ == "__main__":
    pytest.main()
