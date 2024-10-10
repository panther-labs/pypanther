import ast
import pathlib
import tempfile
from typing import Any, Generator, Self

import pytest
from ruamel.yaml import YAML

from pypanther.conversion import actions, util


class AddFunctions(ast.NodeTransformer):
    def __init__(self: Self, functions: dict[str, ast.FunctionDef]) -> None:
        self.functions = functions

    def visit_Module(self: Self, node: ast.Module) -> ast.Module:
        new_body = [
            *[x for x in node.body if not (isinstance(x, ast.FunctionDef) and x.name in set(self.functions.keys()))],
            *self.functions.values(),
        ]
        return ast.Module(
            body=new_body,
            type_ignores=node.type_ignores,
        )


@pytest.fixture()
def temporary_directory() -> Generator[pathlib.Path, None, None]:
    with tempfile.TemporaryDirectory() as temp_dir:
        yield pathlib.Path(temp_dir)


@pytest.fixture()
def panther_analysis_path(temporary_directory: pathlib.Path) -> pathlib.Path:
    util.clone_panther_analysis_main(temporary_directory)
    return temporary_directory


def modify_panther_analysis_rule_metadata(
    panther_analysis_path: pathlib.Path, rule_id: str, values: dict[str, Any],
) -> None:
    rule_metadata_path = util.find_panther_analysis_rule_metadata_path(panther_analysis_path, rule_id)
    yaml = YAML(typ="safe").load(rule_metadata_path)
    for k, v in values.items():
        yaml[k] = v
    YAML(typ="safe").dump(yaml, rule_metadata_path)


def modify_panther_analysis_rule_code(
    panther_analysis_path: pathlib.Path, rule_id: str, functions: dict[str, ast.FunctionDef],
) -> None:
    rule_code_path = util.find_panther_analysis_rule_code_path(panther_analysis_path, rule_id)
    code = ast.parse(rule_code_path.read_text())
    code = AddFunctions(functions).visit(code)
    rule_code_path.write_text(ast.unparse(ast.fix_missing_locations(code)))


def test_convert_rules(panther_analysis_path: pathlib.Path, temporary_directory: pathlib.Path) -> None:
    # arrange

    # modify rules in panther_analysis_path in order to create use cases of customer panther-analysis repositories
    # assumption: panther_analysis_path contains the latest panther-analysis main
    modify_panther_analysis_rule_metadata(
        panther_analysis_path, "Box.New.Login", {"DisplayName": "MODIFIED DISPLAYNAME"},
    )
    modify_panther_analysis_rule_code(
        panther_analysis_path,
        "Box.New.Login",
        {
            x.name: x
            for x in ast.parse(
                """
def title():
    return "MODIFIED TITLE"
""",
            ).body
            if isinstance(x, ast.FunctionDef)
        },
    )

    # act
    actions.convert_rules(panther_analysis_path, temporary_directory)

    # assert
    # make assertions about the structure and contents of files and folders in temporary_directory in order to reflect what's expected
    all_files = [str(x) for x in sorted(temporary_directory.rglob("*"))]
    assert all_files == [
        "pypanther/rules/__init__.py",
        "pypanther/rules/box/__init__.py",
        "pypanther/rules/box/box_new_login.py",
    ]
    converted_rule = ast.parse(temporary_directory.joinpath("pypanther/rules/box/box_new_login.py").read_text())
    classes = [x for x in converted_rule.body if isinstance(x, ast.ClassDef)]
    assert len(classes) == 1
    methods = [x for x in classes[0].body if isinstance(x, ast.FunctionDef)]
    assert len(methods) == 1
    assert methods[0].name == "title"
    attributes = [x for x in classes[0].body if isinstance(x, ast.Assign)]
    assert len(attributes) == 1
    assert len(attributes[0].targets) == 1
    assert isinstance(attributes[0].targets[0], ast.Name)
    assert attributes[0].targets[0].id == "display_name"
