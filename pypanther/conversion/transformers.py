import ast
from typing import Self


class RewritePantherHelperImports(ast.NodeTransformer):
    def __init__(self: Self, helper_module_names: set[str]) -> None:
        self.helper_module_names = helper_module_names

    def visit_Import(self: Self, node: ast.Import) -> ast.AST:
        """
        Rewriting `import ..., ... as ..., ...` statements.

        Transforms this:
        ```
        import panther_config_defaults as pcd, panther_config_overrides
        ```
        to this:
        ```
        import pypanther.helpers.config_defaults as pcd, pypanther.helpers.config_overrides as panther_config_overrides
        ```
        """
        modified_aliases = []
        for alias in node.names:
            modified_alias = alias
            module_name = alias.name.split(".")[0]
            if module_name in self.helper_module_names:
                modified_module_name = f"pypanther.helpers.{module_name}".replace("panther_", "").replace(
                    "_helpers", ""
                )

                modified_asname = None
                if not alias.asname and alias.name.split(".") == 1:
                    modified_asname = alias.name

                modified_alias = ast.alias(name=modified_module_name, asname=modified_asname)

            modified_aliases.append(modified_alias)

        return node

    def visit_ImportFrom(self: Self, node: ast.ImportFrom) -> ast.AST:
        """
        Rewriting `from ... import ...` statements.

        Transforms this:
        ```
        from panther_config import config
        ```
        to this:
        ```
        from pypanther.helpers.config import config
        ```
        """
        # not sure how this can happen
        if not node.module:
            return node

        module_name = node.module.split(".")[0]
        if module_name in self.helper_module_names:
            modified_module_name = module_name.replace("panther_", "").replace("_helpers", "")
            return ast.ImportFrom(module=f"pypanther.helpers.{modified_module_name}", names=node.names)
        return node
