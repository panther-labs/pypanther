import os
import sys
from importlib.util import module_from_spec, spec_from_file_location


class NoMainModuleError(Exception):
    """NoMainModuleError is raised when no main module is found."""


def import_main(target_code_location: str = ".", main_module_name: str = "main"):
    """Imports the main module from the target code location. Assumes `setup` was called first."""
    customer_main_file = main_module_name + ".py"

    path = os.path.join(target_code_location, customer_main_file)
    if not os.path.isfile(path):
        raise NoMainModuleError(f"No {customer_main_file} found")

    sys.path.append(target_code_location)

    spec = spec_from_file_location(main_module_name, path)
    if spec is None:
        raise RuntimeError(f"No spec found for module={main_module_name} and path={path}")
    if spec.loader is None:
        raise RuntimeError(f"Spec has no loader for module={main_module_name} and path={path}")

    module = module_from_spec(spec)
    sys.modules[main_module_name] = module
    spec.loader.exec_module(module)
