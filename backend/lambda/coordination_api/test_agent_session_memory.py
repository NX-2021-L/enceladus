"""Tests for agent_session_memory S3 backend (ENC-TSK-G61)."""
from __future__ import annotations

import io
import unittest

import agent_session_memory as asm


class _FakeS3:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.calls: list[tuple[str, dict]] = []

    def put_object(self, **kwargs):
        self.calls.append(("put_object", kwargs))
        body = kwargs["Body"]
        self.objects[kwargs["Key"]] = body if isinstance(body, bytes) else str(body).encode()

    def get_object(self, **kwargs):
        self.calls.append(("get_object", kwargs))
        key = kwargs["Key"]
        if key not in self.objects:
            raise KeyError(key)
        return {"Body": io.BytesIO(self.objects[key])}

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        if kwargs["Key"] not in self.objects:
            raise OSError("not found")
        return {}

    def list_objects_v2(self, **kwargs):
        self.calls.append(("list_objects_v2", kwargs))
        prefix = kwargs.get("Prefix", "")
        delimiter = kwargs.get("Delimiter")
        contents = []
        prefixes = set()
        for key in self.objects:
            if not key.startswith(prefix):
                continue
            remainder = key[len(prefix) :]
            if delimiter and "/" in remainder:
                prefixes.add(prefix + remainder.split("/", 1)[0] + "/")
                continue
            if remainder:
                contents.append({"Key": key})
        return {
            "Contents": contents,
            "CommonPrefixes": [{"Prefix": p} for p in sorted(prefixes)],
        }

    def delete_object(self, **kwargs):
        self.calls.append(("delete_object", kwargs))
        self.objects.pop(kwargs["Key"], None)

    def copy_object(self, **kwargs):
        self.calls.append(("copy_object", kwargs))
        src = kwargs["CopySource"]["Key"]
        self.objects[kwargs["Key"]] = self.objects[src]


class AgentSessionMemoryTests(unittest.TestCase):
    def setUp(self):
        self.s3 = _FakeS3()
        self.handler = asm.S3MemoryToolHandler(
            self.s3,
            bucket="test-bucket",
            root_key=asm.memory_s3_root_key("coordination-agent-memory", "enceladus", "CRQ-1"),
        )

    def test_memory_scope_id_prefers_session(self):
        self.assertEqual(
            asm.memory_scope_id(request_id="r1", dispatch_id="d1", session_id="s1"),
            "s1",
        )

    def test_create_view_and_str_replace(self):
        out = self.handler.execute(
            {
                "command": "create",
                "path": "/memories/notes.md",
                "file_text": "hello world",
            }
        )
        self.assertIn("created", out)
        view = self.handler.execute({"command": "view", "path": "/memories/notes.md"})
        self.assertIn("hello world", view)
        edited = self.handler.execute(
            {
                "command": "str_replace",
                "path": "/memories/notes.md",
                "old_str": "world",
                "new_str": "gamma",
            }
        )
        self.assertIn("edited successfully", edited)

    def test_rejects_path_outside_memories(self):
        out = self.handler.execute({"command": "view", "path": "/etc/passwd"})
        self.assertIn("must start with /memories", out)

    def test_seed_enceladus_memory_file(self):
        path = asm.seed_enceladus_memory_file(
            self.handler,
            governance_hash="abc123",
            task_id="ENC-TSK-G61",
            plan_id="ENC-PLN-006",
        )
        self.assertEqual(path, "/memories/enceladus_session.json")
        view = self.handler.execute({"command": "view", "path": path})
        self.assertIn("abc123", view)
        self.assertIn("ENC-TSK-G61", view)

    def test_extract_memory_tool_uses(self):
        content = [
            {"type": "text", "text": "checking memory"},
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "memory",
                "input": {"command": "view", "path": "/memories"},
            },
        ]
        uses = asm.extract_memory_tool_uses(content)
        self.assertEqual(len(uses), 1)
        self.assertEqual(uses[0]["id"], "toolu_1")


if __name__ == "__main__":
    unittest.main()
