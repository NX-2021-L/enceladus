"""ENC-TSK-S28-0E: feed_publisher loop guard and version_seq idempotence.

Run: python3 -m pytest test_projection_s28_0e.py -q
"""
import json
import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

import lambda_function as fp


def _rec(mid, vseq, old_extra=None, **extra):
    base = {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-1"}, "version_seq": {"N": str(vseq)}}
    new = {**base, **extra}
    old = {**base, **(old_extra or {})}
    return {"messageId": mid, "body": json.dumps({"eventName": "MODIFY", "dynamodb": {"OldImage": old, "NewImage": new}})}


class FeedIdempotenceTests(unittest.TestCase):
    def test_loop_guard_drops_marker_only_write(self):
        r = _rec("m1", 5, feed_published_version_seq={"N": "5"})
        out, claims, dropped = fp._s28_filter_event({"Records": [r]}, claim_versions=False)
        self.assertEqual((out["Records"], dropped), ([], 1))

    def test_duplicate_and_out_of_order_publish_once_at_highest(self):
        ddb = MagicMock()
        published = {"v": None}
        def update_item(**kw):
            v = int(kw["ExpressionAttributeValues"][":v"]["N"])
            if published["v"] is not None and published["v"] >= v:
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
            prev, published["v"] = published["v"], v
            return {"Attributes": {"feed_published_version_seq": {"N": str(prev)}} if prev else {}}
        ddb.update_item.side_effect = update_item
        recs = [_rec("a", 7, title={"S": "x"}), _rec("b", 5, title={"S": "y"}), _rec("c", 7, title={"S": "x"})]
        out, claims, dropped = fp._s28_filter_event({"Records": recs}, claim_versions=True, ddb=ddb)
        self.assertEqual([r["messageId"] for r in out["Records"]], ["a"])
        self.assertEqual(dropped, 2)
        self.assertEqual(published["v"], 7)

    def test_release_restores_previous_marker(self):
        ddb = MagicMock()
        fp._s28_release_claim(("t", {"k": {"S": "1"}}, 7, {"N": "5"}), ddb)
        self.assertIn("feed_published_version_seq = :prev", ddb.update_item.call_args.kwargs["UpdateExpression"])


if __name__ == "__main__":
    unittest.main()
