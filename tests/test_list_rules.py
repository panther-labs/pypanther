import contextlib
import os.path
from pathlib import Path

import pytest

from pypanther import list_rules
from pypanther.main import setup_parser

LIST_RULES_CMD = "list rules"
MANAGED_ARG = "--managed"
REGISTERED_ARG = "--registered"
FILTER_ARGS = [
    ""  # no filter
    "--log-types a b",
    "--id abc",
    "--create-alert true",
    "--dedup-period-minutes 5",
    "--display-name 5",
    "--enabled true",
    "--summary-attributes a b",
    "--threshold 9",
    "--tags a b",
    "--default-severity low",
    "--default-description desc",
    "--default-reference ref",
    "--default-runbook run",
    "--default-destinations a b",
    "--attributes id default_severity",
    "--output json",
    "--output text",
]


def test_list_no_managed_or_registered() -> None:
    with create_main():
        args = setup_parser().parse_args(f"{LIST_RULES_CMD}".split(" "))
        assert not args.managed and not args.registered
        code, err = list_rules.run(args)
        assert code == 0
        assert err == ""


def test_list_registered_no_main() -> None:
    args = setup_parser().parse_args(f"{LIST_RULES_CMD} {REGISTERED_ARG}".split(" "))
    code, err = list_rules.run(args)
    assert code == 1
    assert err == "No main.py found. Cannot list registered rules without main.py."


@pytest.mark.parametrize("cmd", [f"{LIST_RULES_CMD} {MANAGED_ARG} {f}" for f in FILTER_ARGS])
def test_list_managed_rules(cmd: str) -> None:
    args = setup_parser().parse_args(cmd.split(" "))
    code, err = list_rules.run(args)
    assert code == 0
    assert err == ""


@pytest.mark.parametrize("cmd", [f"{LIST_RULES_CMD} {REGISTERED_ARG} {f}" for f in FILTER_ARGS])
def test_list_registered_rules(cmd: str) -> None:
    with create_main():
        args = setup_parser().parse_args(cmd.split(" "))
        code, err = list_rules.run(args)
        assert code == 0
        assert err == ""


@pytest.mark.parametrize("cmd", [f"{LIST_RULES_CMD} {MANAGED_ARG} {REGISTERED_ARG} {f}" for f in FILTER_ARGS])
def test_list_registered_and_managed_rules(cmd: str) -> None:
    with create_main():
        args = setup_parser().parse_args(cmd.split(" "))
        code, err = list_rules.run(args)
        assert code == 0
        assert err == ""


@contextlib.contextmanager
def create_main():
    """Creates a main.py at the cwd if it does not exist."""
    main_path = Path(os.getcwd()) / "main.py"
    created_main = False

    if not os.path.exists(main_path):
        with open(main_path, "w") as f:
            created_main = True
            f.write("from pypanther import get_panther_rules, register; register(get_panther_rules())")

    try:
        yield
    finally:
        if created_main:
            os.remove(main_path)
