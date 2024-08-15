import pytest

from pypanther import LogType, list_log_types
from pypanther.main import setup_parser

LIST_LOG_TYPES_CMD = "list log-types"
FILTER_ARGS = [
    ""  # no filter
    "--output json",
    "--output text",
]


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


@pytest.mark.parametrize("cmd", [f"{LIST_LOG_TYPES_CMD} {f}" for f in FILTER_ARGS])
def test_list_managed_rules(cmd: str) -> None:
    args = setup_parser().parse_args(cmd.split(" "))
    code, err = list_log_types.run(args)
    assert code == 0
    assert err == ""
