import importlib.util
import pathlib
import re
import sys
from unittest.mock import patch

from botocore.exceptions import ClientError


MODULE_PATH = pathlib.Path(__file__).with_name("parity_audit.py")
SPEC = importlib.util.spec_from_file_location("enceladus_parity_audit_unit", MODULE_PATH)
parity_audit = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = parity_audit
SPEC.loader.exec_module(parity_audit)


class _S3AccessDenied:
    def list_buckets(self):
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "Denied for ListAllMyBuckets",
                }
            },
            "ListBuckets",
        )


class _S3OtherError:
    def list_buckets(self):
        raise ClientError(
            {
                "Error": {
                    "Code": "ThrottlingException",
                    "Message": "request throttled",
                }
            },
            "ListBuckets",
        )


class _EmptyDdb:
    def list_tables(self, **_kwargs):
        return {"TableNames": []}


class _DdbAccessDenied:
    def list_tables(self, **_kwargs):
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Denied for ListTables",
                }
            },
            "ListTables",
        )


class _EmptySqs:
    def list_queues(self, **_kwargs):
        return {}


class _EmptySns:
    def list_topics(self, **_kwargs):
        return {}


class _EmptyEvents:
    def list_rules(self, **_kwargs):
        return {}


class _EmptyPipes:
    def list_pipes(self, **_kwargs):
        return {}


class _EmptyApiGw:
    def get_apis(self, **_kwargs):
        return {"Items": []}


class _EmptyLambda:
    def list_functions(self, **_kwargs):
        return {"Functions": []}


class _LambdaGetFunctionAccessDenied:
    def get_function(self, **_kwargs):
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "missing lambda:GetFunction permission",
                }
            },
            "GetFunction",
        )


def _client_factory(s3_client, ddb_client=None):
    if ddb_client is None:
        ddb_client = _EmptyDdb()

    def _factory(service_name, **_kwargs):
        if service_name == "s3":
            return s3_client
        if service_name == "dynamodb":
            return ddb_client
        if service_name == "sqs":
            return _EmptySqs()
        if service_name == "sns":
            return _EmptySns()
        if service_name == "events":
            return _EmptyEvents()
        if service_name == "pipes":
            return _EmptyPipes()
        if service_name == "apigatewayv2":
            return _EmptyApiGw()
        if service_name == "lambda":
            return _EmptyLambda()
        raise AssertionError(f"Unexpected service_name: {service_name}")

    return _factory


def test_inventory_s3_access_denied_adds_warning_and_continues():
    with patch.object(parity_audit.boto3, "client", side_effect=_client_factory(_S3AccessDenied())):
        inventory = parity_audit._inventory_resources(
            regions=["us-west-2"],
            resource_re=re.compile("enceladus", re.IGNORECASE),
            include_names=set(),
        )

    assert inventory["s3_buckets"] == []
    warnings = inventory.get("inventory_warnings", [])
    assert len(warnings) == 1
    assert warnings[0]["service"] == "s3"
    assert warnings[0]["operation"] == "ListBuckets"
    assert warnings[0]["error_code"] == "AccessDenied"


def test_inventory_s3_non_access_denied_still_raises():
    with patch.object(parity_audit.boto3, "client", side_effect=_client_factory(_S3OtherError())):
        try:
            parity_audit._inventory_resources(
                regions=["us-west-2"],
                resource_re=re.compile("enceladus", re.IGNORECASE),
                include_names=set(),
            )
            assert False, "Expected ClientError for non-access-denied S3 failure"
        except ClientError as exc:
            assert exc.response["Error"]["Code"] == "ThrottlingException"


def test_inventory_dynamodb_access_denied_adds_warning_and_continues():
    with patch.object(
        parity_audit.boto3,
        "client",
        side_effect=_client_factory(_S3AccessDenied(), ddb_client=_DdbAccessDenied()),
    ):
        inventory = parity_audit._inventory_resources(
            regions=["us-west-2"],
            resource_re=re.compile("enceladus", re.IGNORECASE),
            include_names=set(),
        )

    warnings = inventory.get("inventory_warnings", [])
    assert any(
        warning.get("service") == "dynamodb"
        and warning.get("operation") == "ListTables"
        and warning.get("error_code") == "AccessDeniedException"
        and warning.get("region") == "us-west-2"
        for warning in warnings
    )


def test_is_access_denied_accepts_authorization_error_codes():
    err = ClientError(
        {
            "Error": {
                "Code": "AuthorizationErrorException",
                "Message": "not authorized",
            }
        },
        "ListTopics",
    )
    assert parity_audit._is_access_denied(err) is True


def test_lambda_parity_get_function_access_denied_is_non_fatal(tmp_path):
    entry = tmp_path / "handlers" / "auth.py"
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text("def handler(event, context):\n    return {'ok': True}\n", encoding="utf-8")

    mappings = [
        {
            "function_name": "auth-refresh",
            "region": "us-west-2",
            "repo_entry_path": str(entry.relative_to(tmp_path)),
            "entry_file": "auth.py",
        }
    ]

    def _lambda_factory(service_name, **_kwargs):
        assert service_name == "lambda"
        return _LambdaGetFunctionAccessDenied()

    with patch.object(parity_audit.boto3, "client", side_effect=_lambda_factory):
        parity = parity_audit._audit_lambda_parity(mappings=mappings, repo_root=tmp_path)

    assert parity["stats"]["ACCESS_DENIED"] == 1
    assert parity["stats"]["ERROR"] == 0
    assert parity["results"][0]["status"] == "ACCESS_DENIED"
    assert parity["results"][0]["function_name"] == "auth-refresh"
