import os
import unittest
from pathlib import Path

import pytest

from pypanther import LogType, list_log_types
from pypanther.main import setup_parser
from pypanther.schemas import Manager as SchemaManager

LIST_LOG_TYPES_CMD = "list log-types --schemas-path tests/fixtures/custom_schemas/valid"
FILTER_ARGS = [
    ""  # no filter
    "--output json",
    "--output text",
]
fixtures_dir = Path(__file__).parent / Path("fixtures")
FIXTURES_PATH = fixtures_dir.absolute()


def test_list_log_types(capsys) -> None:
    args = setup_parser().parse_args(f"{LIST_LOG_TYPES_CMD}".split(" "))
    code, err = list_log_types.run(args)
    assert code == 0
    assert err == ""

    std = capsys.readouterr()
    for log_type in LogType:
        assert str(log_type) in std.out


def test_list_log_types_substring(capsys) -> None:
    args = setup_parser().parse_args(f"{LIST_LOG_TYPES_CMD} zee".split(" "))
    code, err = list_log_types.run(args)
    assert code == 0
    assert err == ""

    std = capsys.readouterr()
    assert str(LogType.ZEEK_DNS) in std.out
    assert str(LogType.OKTA_SYSTEM_LOG) not in std.out


class TestUploader(unittest.TestCase):
    def test_print_custom_local_logtypes(self):
        path = os.path.join(FIXTURES_PATH, "custom_schemas/valid")
        manager = SchemaManager(path, False, False)
        self.assertEqual(
            sorted([schema_mod_obj.name for schema_mod_obj in manager.schemas]),
            sorted(
                [
                    "Custom.SampleSchema1",
                    "Custom.SampleSchema2",
                    "Custom.Sample.Schema3",
                    "Custom.AWSAccountIDs",
                ],
            ),
        )


@pytest.mark.parametrize("cmd", [f"{LIST_LOG_TYPES_CMD} {f}" for f in FILTER_ARGS])
def test_list_managed_rules(cmd: str) -> None:
    args = setup_parser().parse_args(cmd.split(" "))
    code, err = list_log_types.run(args)
    assert code == 0
    assert err == ""
