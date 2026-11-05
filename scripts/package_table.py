"""Loads the package table (package_expected.py) for check_packages.py and check_tss_deps.py, so both read one file.

CUSTODIO_PACKAGE_EXPECTED=<path to a copy of package_expected.py> makes both read that copy instead (the tests edit a copy).
"""
import importlib.util
import os
import sys


def load():
    path = os.environ.get("CUSTODIO_PACKAGE_EXPECTED") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "package_expected.py")
    spec = importlib.util.spec_from_file_location("package_expected", path)
    if spec is None or spec.loader is None or not os.path.isfile(path):
        sys.exit(f"package table: cannot read {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
