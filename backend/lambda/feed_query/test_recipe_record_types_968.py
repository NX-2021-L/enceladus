"""DVP-TSK-968: feed_query accepts recipe and recipe_run record types."""
import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent


def _load():
    sys.path.insert(0, str(HERE))
    spec = importlib.util.spec_from_file_location("feed_query_lf_968", HERE / "lambda_function.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recipe_types_are_valid_record_types():
    lf = _load()
    assert {"recipe", "recipe_run"} <= lf.VALID_RECORD_TYPES
    assert {"task", "issue", "feature", "lesson", "plan"} <= lf.VALID_RECORD_TYPES
