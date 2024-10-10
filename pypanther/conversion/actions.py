import ast
import logging
import pathlib
import tempfile

from ruamel.yaml import YAML

from pypanther.conversion import models, transformers, util

logger = logging.getLogger(__name__)


def convert_panther_analysis(panther_analysis_path: pathlib.Path, output_path: pathlib.Path) -> None:
    # known conventions
    v1_helpers_path = panther_analysis_path / "global_helpers"
    v1_data_models_path = panther_analysis_path / "data_models"
    _v1_rules_path = panther_analysis_path / "rules"

    v1_helpers = _read_v1_helpers(v1_helpers_path)
    v1_data_models = _read_v1_data_models(v1_data_models_path)

    v1_helper_module_names = {x.module.name for x in v1_helpers}

    helpers = _convert_v1_helpers(v1_helper_module_names, v1_helpers)
    _helpers_package = models.PythonPackage(name="helpers", init_code=None, modules=helpers, subpackages=[])

    data_models = _convert_v1_data_models(v1_helper_module_names, v1_data_models)
    _data_models_package = models.PythonPackage(name="data_models", init_code=None, modules=data_models, subpackages=[])

    _pypanther_package = models.PythonPackage(
        name="pypanther",
        init_code=None,
        modules=[],
        subpackages=[_helpers_package, _data_models_package],
    )
    _write_python_package(_pypanther_package, output_path)


def convert_rules(panther_analysis_path: pathlib.Path, output_path: pathlib.Path) -> None:
    breakpoint()
    # read local rules
    v1_rules_path = panther_analysis_path / "rules"
    local_rules = read_v1_rules(v1_rules_path)

    # fetch panther-analysis main
    with tempfile.TemporaryDirectory() as temp_dir:
        panther_analysis_main_path = pathlib.Path(temp_dir)
        util.clone_panther_analysis_main(panther_analysis_main_path)
        panther_analysis_main_rules = read_v1_rules(panther_analysis_main_path)

        for id_ in local_rules:
            # compare metadata
            local_rule_metadata_dict = local_rules[id_].metadata.model_dump()
            panther_analysis_main_rule_metadata_dict = panther_analysis_main_rules[id_].metadata.model_dump()
            yaml_diff = set()
            for k, v in local_rule_metadata_dict.items():
                if (
                    k not in panther_analysis_main_rule_metadata_dict
                    or v != panther_analysis_main_rule_metadata_dict[k]
                ):
                    yaml_diff.add(k)
            # compare module

    # compare local with panther-analysis main
    # properly convert:
    # - if only yaml, create overrides
    # - if python changed, create new python class
    # write stuff
    raise NotImplementedError


def _read_v1_helpers(v1_helpers_path: pathlib.Path) -> list[models.V1Helper]:
    v1_helpers: list[models.V1Helper] = []
    for path in v1_helpers_path.rglob("*.y*ml"):
        yaml = YAML(typ="safe").load(path)
        metadata = models.V1HelperMetadata(**yaml)

        code_path = v1_helpers_path / metadata.filename
        code = ast.parse(code_path.read_text())
        module = models.PythonModule(name=metadata.filename.removesuffix(".py"), code=code)

        v1_helper = models.V1Helper(metadata=metadata, module=module)

        if v1_helper.metadata.analysis_type != models.AnalysisType.GLOBAL:
            logger.error("AnalysisType must be 'global' analysis_type=%s", v1_helper.metadata.analysis_type)
            continue

        v1_helpers.append(v1_helper)

    return v1_helpers


def _read_v1_data_models(v1_data_models_path: pathlib.Path) -> list[models.V1DataModel]:
    v1_data_models = []
    for path in v1_data_models_path.rglob("*.y*ml"):
        yaml = YAML(typ="safe").load(path)
        metadata = models.V1DataModelMetadata(**yaml)

        code_path = v1_data_models_path / metadata.filename
        code = ast.parse(code_path.read_text())
        module = models.PythonModule(name=metadata.filename.removesuffix(".py"), code=code)

        v1_data_model = models.V1DataModel(metadata=metadata, module=module)

        if v1_data_model.metadata.analysis_type != models.AnalysisType.DATAMODEL:
            logger.error("AnalysisType must be 'datamodel' analysis_type=%s", v1_data_model.metadata.analysis_type)
            continue

        v1_data_models.append(v1_data_model)

    return v1_data_models


def read_v1_rules(v1_rules_path: pathlib.Path) -> dict[str, models.V1Rule]:
    v1_rules: dict[str, models.V1Rule] = {}
    for path in v1_rules_path.rglob("*.y*ml"):
        print(path)
        yaml = YAML(typ="safe").load(path)

        if "Filename" not in yaml:
            logger.warning("missing code file for rule path=%s", path)
            continue

        metadata = models.V1RuleMetadata(**yaml)

        code_path = path.parent / metadata.filename
        code = ast.parse(code_path.read_text())
        module = models.PythonModule(name=metadata.filename.removesuffix(".py"), code=code)

        v1_rule = models.V1Rule(metadata=metadata, module=module)

        if v1_rule.metadata.analysis_type not in {models.AnalysisType.RULE, models.AnalysisType.SCHEDULED_RULE}:
            logger.error(
                "AnalysisType must be 'rule' or 'scheduled_rule' analysis_type=%s",
                v1_rule.metadata.analysis_type,
            )
            continue

        v1_rules[v1_rule.metadata.rule_id] = v1_rule

    return v1_rules


def _convert_v1_helpers(
    v1_helper_module_names: set[str], v1_helpers: list[models.V1Helper],
) -> list[models.PythonModule]:
    helpers = []
    for v1_helper in v1_helpers:
        helper_module_name = v1_helper.module.name.replace("_helpers", "").replace("panther_", "")
        helper_code = transformers.RewritePantherHelperImports(v1_helper_module_names).visit(v1_helper.module.code)
        helper = models.PythonModule(name=helper_module_name, code=helper_code)
        helpers.append(helper)

    return helpers


def _convert_v1_data_models(
    v1_helper_module_names: set[str],
    v1_data_models: list[models.V1DataModel],
) -> list[models.PythonModule]:
    data_models = []
    for v1_data_model in v1_data_models:
        code = ast.Module(
            type_ignores=[],
            body=[
                ast.ImportFrom(
                    module="pypanther.base",
                    names=[
                        ast.alias("DataModel"),
                        ast.alias("DataModelMapping"),
                        ast.alias("LogType"),
                    ],
                ),
                ast.ClassDef(
                    name=_to_ascii(v1_data_model.metadata.data_model_id),
                    bases=[ast.Name(id="DataModel")],
                    keywords=[],
                    decorator_list=[],
                    body=[
                        ast.AnnAssign(
                            target=ast.Name(id="id"),
                            annotation=ast.Name(id="str"),
                            value=ast.Constant(value=v1_data_model.metadata.data_model_id),
                            simple=1,
                        ),
                        ast.AnnAssign(
                            target=ast.Name(id="display_name"),
                            annotation=ast.Name(id="str"),
                            value=ast.Constant(value=v1_data_model.metadata.display_name),
                            simple=1,
                        ),
                        ast.AnnAssign(
                            target=ast.Name(id="enabled"),
                            annotation=ast.Name(id="bool"),
                            value=ast.Constant(value=v1_data_model.metadata.enabled),
                            simple=1,
                        ),
                        ast.AnnAssign(
                            target=ast.Name(id="log_types"),
                            annotation=ast.Subscript(
                                value=ast.Name(id="list"),
                                slice=ast.Index(value=ast.Name(id="str")),
                            ),
                            value=ast.List(
                                elts=[
                                    ast.Name(
                                        # TODO: add better validation for this
                                        id=f"LogType.{x.replace('.', '_').upper()}",
                                        ctx=ast.Load(),
                                    )
                                    for x in v1_data_model.metadata.log_types
                                ],
                            ),
                            simple=1,
                        ),
                        ast.AnnAssign(
                            target=ast.Name(id="mappings"),
                            annotation=ast.Subscript(
                                value=ast.Name(id="list"),
                                slice=ast.Index(value=ast.Name(id="DataModelMapping")),
                            ),
                            value=ast.List(
                                elts=[
                                    ast.Call(
                                        func=ast.Name(id="DataModelMapping"),
                                        args=[],
                                        keywords=[
                                            ast.keyword(arg="name", value=x.name),
                                            ast.keyword(
                                                arg="method" if x.method else "path",
                                                value=ast.Name(id=x.method) if x.method else ast.Constant(value=x.path),
                                            ),
                                        ],
                                    )
                                    for x in v1_data_model.metadata.mappings
                                ],
                            ),
                            simple=1,
                        ),
                    ],
                ),
                *v1_data_model.module.code.body,
            ],
        )
        data_model_module_name = v1_data_model.module.name.replace("_data_model", "")
        data_model_code = transformers.RewritePantherHelperImports(v1_helper_module_names).visit(code)
        data_model = models.PythonModule(name=data_model_module_name, code=data_model_code)
        data_models.append(data_model)

    return data_models


def _write_helpers(helpers: list[models.PythonModule], helpers_output_path: pathlib.Path) -> None:
    for helper in helpers:
        helper_path = helpers_output_path / (helper.name + ".py")
        with helper_path.open("w") as fp:
            fp.write(ast.unparse(helper.code))


def _write_python_package(python_package: models.PythonPackage, output_path: pathlib.Path) -> None:
    # TODO: remember to add __init__.py files
    raise NotImplementedError


def _to_ascii(s: str) -> str:
    ret = "".join([i if ord("A") <= ord(i) <= ord("z") or ord("0") <= ord(i) < ord("9") else "" for i in s])

    while ret[0].isdigit():
        ret = ret[1:]

    return ret
