"""test_gamma_content_fallback_m59.py — _get_content stored-s3_key fallback.

ENC-TSK-M59 / ENC-ISS-526: gamma's documents table carries rows cloned from
prod whose s3_key points at the unprefixed prod path, while gamma's
document_api computes an env-prefixed key that was never provisioned. These
tests pin the fallback contract:

  1. computed key hit -> stored key never consulted, no copy
  2. computed miss + stored key hit -> content served + lazily copied to the
     computed key
  3. computed miss + no stored key -> None (legacy behavior)
  4. computed miss + stored key == computed key -> None (no self-fallback)
  5. fallback AccessDenied (IAM grant not yet applied) -> None, no raise
  6. lazy-copy failure is swallowed -> content still served
  7. computed-key non-NoSuchKey errors still raise (config errors stay loud)

Run: python3 -m pytest test_gamma_content_fallback_m59.py -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "document_api",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


class _NoSuchKey(Exception):
    pass


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "GetObject")


def _body(text: str) -> dict:
    stream = MagicMock()
    stream.read.return_value = text.encode("utf-8")
    return {"Body": stream}


def _make_s3(objects: dict, get_errors: dict | None = None) -> MagicMock:
    """Mock S3 client backed by {(bucket, key): content}.

    get_errors maps (bucket, key) -> ClientError to raise for that location.
    Missing keys raise s3.exceptions.NoSuchKey like the real client.
    """
    s3 = MagicMock()
    s3.exceptions.NoSuchKey = _NoSuchKey
    get_errors = get_errors or {}

    def get_object(Bucket, Key):
        if (Bucket, Key) in get_errors:
            raise get_errors[(Bucket, Key)]
        if (Bucket, Key) in objects:
            return _body(objects[(Bucket, Key)])
        raise _NoSuchKey()

    s3.get_object.side_effect = get_object
    return s3


BUCKET = document_api.S3_BUCKET
PREFIX = document_api.S3_PREFIX
COMPUTED = f"{PREFIX}/enceladus/DOC-TEST.md"
STORED = "agent-documents-prod/enceladus/DOC-TEST.md"


class GetContentFallbackTests(unittest.TestCase):
    def test_computed_key_hit_skips_fallback(self):
        s3 = _make_s3({(BUCKET, COMPUTED): "primary-body"})
        with patch.object(document_api, "_get_s3", return_value=s3):
            out = document_api._get_content(
                "enceladus", "DOC-TEST", stored_s3_key=STORED
            )
        self.assertEqual(out, "primary-body")
        self.assertEqual(s3.get_object.call_count, 1)
        s3.put_object.assert_not_called()

    def test_computed_miss_falls_back_and_lazily_provisions(self):
        s3 = _make_s3({(BUCKET, STORED): "prod-body"})
        with patch.object(document_api, "_get_s3", return_value=s3):
            out = document_api._get_content(
                "enceladus", "DOC-TEST", stored_s3_key=STORED
            )
        self.assertEqual(out, "prod-body")
        s3.put_object.assert_called_once()
        kwargs = s3.put_object.call_args.kwargs
        self.assertEqual(kwargs["Bucket"], BUCKET)
        self.assertEqual(kwargs["Key"], COMPUTED)
        self.assertEqual(kwargs["Body"], b"prod-body")

    def test_computed_miss_without_stored_key_returns_none(self):
        s3 = _make_s3({})
        with patch.object(document_api, "_get_s3", return_value=s3):
            out = document_api._get_content("enceladus", "DOC-TEST")
        self.assertIsNone(out)
        s3.put_object.assert_not_called()

    def test_stored_key_equal_to_computed_does_not_self_fallback(self):
        s3 = _make_s3({})
        with patch.object(document_api, "_get_s3", return_value=s3):
            out = document_api._get_content(
                "enceladus", "DOC-TEST", stored_s3_key=COMPUTED
            )
        self.assertIsNone(out)
        self.assertEqual(s3.get_object.call_count, 1)

    def test_fallback_access_denied_returns_none(self):
        s3 = _make_s3(
            {}, get_errors={(BUCKET, STORED): _client_error("AccessDenied")}
        )
        with patch.object(document_api, "_get_s3", return_value=s3):
            out = document_api._get_content(
                "enceladus", "DOC-TEST", stored_s3_key=STORED
            )
        self.assertIsNone(out)
        s3.put_object.assert_not_called()

    def test_lazy_copy_failure_still_serves_content(self):
        s3 = _make_s3({(BUCKET, STORED): "prod-body"})
        s3.put_object.side_effect = _client_error("AccessDenied")
        with patch.object(document_api, "_get_s3", return_value=s3):
            out = document_api._get_content(
                "enceladus", "DOC-TEST", stored_s3_key=STORED
            )
        self.assertEqual(out, "prod-body")

    def test_stored_bucket_override_is_honored(self):
        s3 = _make_s3({("other-bucket", STORED): "cross-bucket-body"})
        with patch.object(document_api, "_get_s3", return_value=s3):
            out = document_api._get_content(
                "enceladus",
                "DOC-TEST",
                stored_s3_key=STORED,
                stored_s3_bucket="other-bucket",
            )
        self.assertEqual(out, "cross-bucket-body")
        kwargs = s3.put_object.call_args.kwargs
        self.assertEqual(kwargs["Bucket"], BUCKET)
        self.assertEqual(kwargs["Key"], COMPUTED)

    def test_primary_non_nosuchkey_error_still_raises(self):
        s3 = _make_s3(
            {}, get_errors={(BUCKET, COMPUTED): _client_error("SlowDown")}
        )
        with patch.object(document_api, "_get_s3", return_value=s3):
            with self.assertRaises(ClientError):
                document_api._get_content(
                    "enceladus", "DOC-TEST", stored_s3_key=STORED
                )


if __name__ == "__main__":
    unittest.main()
