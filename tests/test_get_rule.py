import argparse
import contextlib
import os
from pathlib import Path
from typing import Type

import pytest

from pypanther.base import TYPE_RULE, Rule
from pypanther.display import COMMON_CLI_OUTPUT_TYPES
from pypanther.get import get_panther_rules
from pypanther.get_rule import run
from pypanther.log_types import LogType
from pypanther.registry import _RULE_REGISTRY, register
from pypanther.severity import Severity


class TestRun:
    def test_not_found(self) -> None:
        with create_main():
            rule_id = "Not.A.Real.ID"
            rc, err_msg = run(
                argparse.Namespace(id=rule_id, type=TYPE_RULE.lower(), output="text", class_definition=False),
            )
            assert rc == 1
            assert rule_id in err_msg and "no" in err_msg

    def test_multiple_found(self) -> None:
        with create_main():
            rule_id = "GitHub.Team.Modified-prototype"

            class DupIDRule(Rule):
                id = rule_id
                log_types = [LogType.OKTA_SYSTEM_LOG]
                default_severity = Severity.INFO

                def rule(self, _):
                    pass

            register(DupIDRule)
            rc, err_msg = run(
                argparse.Namespace(id=rule_id, type=TYPE_RULE.lower(), output="text", class_definition=False),
            )
            assert rc == 1
            assert rule_id in err_msg and "multiple" in err_msg
            _RULE_REGISTRY.clear()

    def test_invalid_output(self) -> None:
        with create_main():
            rule_id = "GitHub.Team.Modified-prototype"
            fake_output = "fake_output"
            rc, err_msg = run(
                argparse.Namespace(id=rule_id, type=TYPE_RULE.lower(), output=fake_output, class_definition=False),
            )
            assert rc == 1
            assert fake_output in err_msg

    @pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
    def test_happy_path_managed_text(self, rule: Type[Rule]) -> None:
        with create_main():
            rc, err_msg = run(
                argparse.Namespace(id=rule.id, type=TYPE_RULE.lower(), output="text", class_definition=False),
            )
            assert rc == 0
            assert err_msg == ""

    @pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
    def test_happy_path_managed_json(self, rule: Type[Rule]) -> None:
        with create_main():
            rc, err_msg = run(
                argparse.Namespace(id=rule.id, type=TYPE_RULE.lower(), output="json", class_definition=False),
            )
            assert rc == 0
            assert err_msg == ""

    @pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
    def test_happy_path_managed_text_class_definition(self, rule: Type[Rule]) -> None:
        with create_main():
            rc, err_msg = run(
                argparse.Namespace(id=rule.id, type=TYPE_RULE.lower(), output="text", class_definition=True),
            )
            assert rc == 0
            assert err_msg == ""

    @pytest.mark.parametrize("rule", get_panther_rules(), ids=lambda x: x.id)
    def test_happy_path_managed_json_class_definition(self, rule: Type[Rule]) -> None:
        with create_main():
            rc, err_msg = run(
                argparse.Namespace(id=rule.id, type=TYPE_RULE.lower(), output="json", class_definition=True),
            )
            assert rc == 0
            assert err_msg == ""

    @pytest.mark.parametrize("output", COMMON_CLI_OUTPUT_TYPES)
    def test_happy_path_registered(self, output: str) -> None:
        with create_main():
            rule_id = "Custom.Rule.ID"

            class CustomRule(Rule):
                id = rule_id
                log_types = [LogType.OKTA_SYSTEM_LOG]
                default_severity = Severity.INFO

                def rule(self, _):
                    pass

            register(CustomRule)
            rc, err_msg = run(
                argparse.Namespace(id=rule_id, type=TYPE_RULE.lower(), output=output, class_definition=False),
            )
            assert rc == 0
            assert err_msg == ""
            _RULE_REGISTRY.clear()


if __name__ == "__main__":
    pytest.main()


@contextlib.contextmanager
def create_main():
    """Creates a main.py at the cwd if it does not exist."""
    main_path = Path(os.getcwd()) / "main.py"
    created_main = False

    if not os.path.exists(main_path):
        with open(main_path, "w") as f:
            created_main = True
            f.write("")

    try:
        yield
    finally:
        if created_main:
            os.remove(main_path)
