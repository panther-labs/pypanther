import ast
import pathlib

import git
from ruamel.yaml import YAML

from pypanther.conversion import models


class PantherAnalysisRuleNotFoundError(Exception):
    pass


def clone_panther_analysis_main(output_dir: pathlib.Path) -> None:
    if not output_dir.is_dir() or not output_dir.exists():
        raise ValueError(f"{output_dir} is not a directory")

    # git clone --depth 1 --branch main --single-branch https://github.com/panther-labs/panther-analysis.git output_dir
    git.Repo.clone_from(
        url="https://github.com/panther-labs/panther-analysis.git",
        to_path=output_dir,
        branch="main",
        depth=1,
        no_single_branch=False,
    )


def compare_ast(node1: ast.AST, node2: ast.AST) -> bool:
    if type(node1) is not type(node2):
        return False

    if isinstance(node1, list):
        # node2 is a list too but the type checker cannot understand it
        assert isinstance(node2, list)

        return len(node1) == len(node2) and all(compare_ast(n1, n2) for n1, n2 in zip(node1, node2))

    if isinstance(node1, ast.AST):
        for k, v in vars(node1).items():
            if k in ("lineno", "col_offset"):
                continue
            if not compare_ast(v, getattr(node2, k)):
                return False
        return True

    return node1 == node2


def compare_rules(rule1: models.V1Rule, rule2: models.V1Rule) -> bool:
    return (
        rule1.metadata == rule2.metadata
        and rule1.module.name == rule2.module.name
        and compare_ast(rule1.module.code, rule2.module.code)
    )


def find_panther_analysis_rule_metadata_path(panther_analysis_path: pathlib.Path, rule_id: str) -> pathlib.Path:
    for path in panther_analysis_path.rglob("*.y*ml"):
        yaml = YAML(typ="safe").load(path)
        if yaml["RuleID"] == rule_id:
            return path

    raise PantherAnalysisRuleNotFoundError


def find_panther_analysis_rule_code_path(panther_analysis_path: pathlib.Path, rule_id: str) -> pathlib.Path:
    rule_metadata_path = find_panther_analysis_rule_metadata_path(panther_analysis_path, rule_id)
    yaml = YAML(typ="safe").load(rule_metadata_path)
    return rule_metadata_path.parent.joinpath(yaml["Filename"])
