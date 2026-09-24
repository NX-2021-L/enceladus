"""S3-backed handler for Anthropic memory_20250818 tool (ENC-TSK-G61).

Maps Claude's virtual /memories paths to S3 keys under:
  s3://{bucket}/{prefix}/{project_id}/{scope_id}/memories/...
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

MEMORY_COMMANDS = ("view", "create", "str_replace", "insert", "delete", "rename")
ALLOWED_FILE_SUFFIXES = (".txt", ".md", ".json", ".py", ".yaml", ".yml", ".xml")


def memory_scope_id(
    *,
    request_id: str = "",
    dispatch_id: str = "",
    session_id: str = "",
) -> str:
    """Derive a stable S3 namespace for one coordination memory store."""
    for candidate in (session_id, request_id, dispatch_id):
        cleaned = str(candidate or "").strip()
        if cleaned:
            return cleaned.replace("/", "_")[:128]
    return "anonymous"


def memory_s3_root_key(prefix: str, project_id: str, scope_id: str) -> str:
    base = "/".join(
        part.strip("/")
        for part in (prefix, project_id or "unknown", scope_id, "memories")
        if str(part or "").strip()
    )
    return f"{base}/"


def _validate_memory_path(path: str) -> str:
    if not str(path or "").startswith("/memories"):
        raise ValueError(
            f"Path must start with /memories, got: {path}. "
            "All memory operations must be confined to the /memories directory."
        )
    relative = str(path)[len("/memories") :].lstrip("/")
    if ".." in relative.split("/"):
        raise ValueError(f"Path '{path}' would escape /memories directory.")
    return relative


def _object_key(root_key: str, relative_path: str) -> str:
    if not relative_path:
        return root_key
    return f"{root_key}{relative_path}"


def _format_result(result: Dict[str, str]) -> str:
    if result.get("success"):
        return str(result["success"])
    return str(result.get("error") or "memory command failed")


class S3MemoryToolHandler:
    """Execute memory_20250818 commands against S3."""

    def __init__(self, s3_client: Any, *, bucket: str, root_key: str):
        self._s3 = s3_client
        self._bucket = bucket
        self._root_key = root_key if root_key.endswith("/") else f"{root_key}/"

    def execute(self, tool_input: Dict[str, Any]) -> str:
        command = str(tool_input.get("command") or "").strip()
        try:
            if command == "view":
                out = self._view(tool_input)
            elif command == "create":
                out = self._create(tool_input)
            elif command == "str_replace":
                out = self._str_replace(tool_input)
            elif command == "insert":
                out = self._insert(tool_input)
            elif command == "delete":
                out = self._delete(tool_input)
            elif command == "rename":
                out = self._rename(tool_input)
            else:
                out = {
                    "error": f"Unknown command: '{command}'. "
                    f"Valid commands: {', '.join(MEMORY_COMMANDS)}"
                }
        except ValueError as exc:
            out = {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            out = {"error": f"Unexpected error executing {command}: {exc}"}
        return _format_result(out)

    def _list_directory(self, prefix_key: str) -> List[str]:
        resp = self._s3.list_objects_v2(
            Bucket=self._bucket,
            Prefix=prefix_key,
            Delimiter="/",
        )
        items: List[str] = []
        for common in resp.get("CommonPrefixes") or []:
            name = str(common.get("Prefix") or "")
            if name.startswith(prefix_key):
                items.append(name[len(prefix_key) :].rstrip("/") + "/")
        for obj in resp.get("Contents") or []:
            key = str(obj.get("Key") or "")
            if key == prefix_key or not key.startswith(prefix_key):
                continue
            rel = key[len(prefix_key) :]
            if "/" in rel:
                continue
            if rel and not rel.startswith("."):
                items.append(rel)
        return sorted(items)

    def _read_text(self, key: str) -> str:
        resp = self._s3.get_object(Bucket=self._bucket, Key=key)
        return resp["Body"].read().decode("utf-8")

    def _write_text(self, key: str, text: str) -> None:
        self._s3.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=text.encode("utf-8"),
            ContentType="text/plain; charset=utf-8",
        )

    def _object_exists(self, key: str) -> bool:
        try:
            self._s3.head_object(Bucket=self._bucket, Key=key)
            return True
        except Exception:
            return False

    def _is_directory(self, key: str) -> bool:
        if self._object_exists(key):
            return False
        resp = self._s3.list_objects_v2(Bucket=self._bucket, Prefix=key, MaxKeys=1)
        return bool(resp.get("Contents") or resp.get("CommonPrefixes"))

    def _view(self, params: Dict[str, Any]) -> Dict[str, str]:
        path = params.get("path")
        view_range = params.get("view_range")
        if not path:
            return {"error": "Missing required parameter: path"}
        relative = _validate_memory_path(str(path))
        key = _object_key(self._root_key, relative)

        if not relative or self._is_directory(key):
            items = self._list_directory(key)
            if not items:
                return {"success": f"Directory: {path}\n(empty)"}
            return {"success": f"Directory: {path}\n" + "\n".join(f"- {item}" for item in items)}

        if not self._object_exists(key):
            return {"error": f"Path not found: {path}"}
        try:
            content = self._read_text(key)
        except UnicodeDecodeError:
            return {"error": f"Cannot read {path}: File is not valid UTF-8 text"}
        lines = content.splitlines()
        if view_range and isinstance(view_range, list) and len(view_range) >= 2:
            start_line = max(1, int(view_range[0])) - 1
            end_line = len(lines) if int(view_range[1]) == -1 else int(view_range[1])
            lines = lines[start_line:end_line]
            start_num = start_line + 1
        else:
            start_num = 1
        numbered = [f"{i + start_num:4d}: {line}" for i, line in enumerate(lines)]
        return {"success": "\n".join(numbered)}

    def _create(self, params: Dict[str, Any]) -> Dict[str, str]:
        path = params.get("path")
        file_text = params.get("file_text", "")
        if not path:
            return {"error": "Missing required parameter: path"}
        path_str = str(path)
        if not path_str.endswith(ALLOWED_FILE_SUFFIXES):
            return {
                "error": f"Cannot create {path}: Only text files are supported. "
                f"Use extensions: {', '.join(ALLOWED_FILE_SUFFIXES)}"
            }
        relative = _validate_memory_path(path_str)
        key = _object_key(self._root_key, relative)
        self._write_text(key, str(file_text or ""))
        return {"success": f"File created successfully at {path}"}

    def _str_replace(self, params: Dict[str, Any]) -> Dict[str, str]:
        path = params.get("path")
        old_str = params.get("old_str")
        new_str = params.get("new_str", "")
        if not path or old_str is None:
            return {"error": "Missing required parameters: path, old_str"}
        relative = _validate_memory_path(str(path))
        key = _object_key(self._root_key, relative)
        if not self._object_exists(key):
            return {"error": f"File not found: {path}"}
        content = self._read_text(key)
        count = content.count(str(old_str))
        if count == 0:
            return {"error": f"String not found in {path}. The exact text must exist in the file."}
        if count > 1:
            return {
                "error": f"String appears {count} times in {path}. "
                "The string must be unique. Use more specific context."
            }
        self._write_text(key, content.replace(str(old_str), str(new_str), 1))
        return {"success": f"File {path} has been edited successfully"}

    def _insert(self, params: Dict[str, Any]) -> Dict[str, str]:
        path = params.get("path")
        insert_line = params.get("insert_line")
        insert_text = params.get("insert_text", "")
        if not path or insert_line is None:
            return {"error": "Missing required parameters: path, insert_line"}
        relative = _validate_memory_path(str(path))
        key = _object_key(self._root_key, relative)
        if not self._object_exists(key):
            return {"error": f"File not found: {path}"}
        lines = self._read_text(key).splitlines()
        line_no = int(insert_line)
        if line_no < 0 or line_no > len(lines):
            return {
                "error": f"Invalid insert_line {line_no}. Must be between 0 and {len(lines)}"
            }
        lines.insert(line_no, str(insert_text).rstrip("\n"))
        self._write_text(key, "\n".join(lines) + ("\n" if lines else ""))
        return {"success": f"Text inserted at line {line_no} in {path}"}

    def _delete(self, params: Dict[str, Any]) -> Dict[str, str]:
        path = params.get("path")
        if not path:
            return {"error": "Missing required parameter: path"}
        if str(path) == "/memories":
            return {"error": "Cannot delete the /memories directory itself"}
        relative = _validate_memory_path(str(path))
        key = _object_key(self._root_key, relative)
        if self._object_exists(key):
            self._s3.delete_object(Bucket=self._bucket, Key=key)
            return {"success": f"File deleted: {path}"}
        if self._is_directory(key):
            resp = self._s3.list_objects_v2(Bucket=self._bucket, Prefix=key)
            for obj in resp.get("Contents") or []:
                obj_key = str(obj.get("Key") or "")
                if obj_key:
                    self._s3.delete_object(Bucket=self._bucket, Key=obj_key)
            return {"success": f"Directory deleted: {path}"}
        return {"error": f"Path not found: {path}"}

    def _rename(self, params: Dict[str, Any]) -> Dict[str, str]:
        old_path = params.get("old_path")
        new_path = params.get("new_path")
        if not old_path or not new_path:
            return {"error": "Missing required parameters: old_path, new_path"}
        old_rel = _validate_memory_path(str(old_path))
        new_rel = _validate_memory_path(str(new_path))
        old_key = _object_key(self._root_key, old_rel)
        new_key = _object_key(self._root_key, new_rel)
        if not self._object_exists(old_key):
            return {"error": f"Source path not found: {old_path}"}
        if self._object_exists(new_key):
            return {"error": f"Destination already exists: {new_path}"}
        self._s3.copy_object(
            Bucket=self._bucket,
            CopySource={"Bucket": self._bucket, "Key": old_key},
            Key=new_key,
        )
        self._s3.delete_object(Bucket=self._bucket, Key=old_key)
        return {"success": f"Renamed {old_path} to {new_path}"}


def seed_enceladus_memory_file(
    handler: S3MemoryToolHandler,
    *,
    governance_hash: str = "",
    task_id: str = "",
    plan_id: str = "",
) -> Optional[str]:
    """Create default session memory file if missing (schema-aligned bootstrap)."""
    path = "/memories/enceladus_session.json"
    result = handler.execute({"command": "view", "path": path})
    if "Path not found" not in result:
        return None
    payload = {
        "plan_anchors": [{"id": pid, "note": "active plan"} for pid in [plan_id] if pid],
        "active_governance_hash": governance_hash,
        "active_task_state": {"task_id": task_id} if task_id else {},
    }
    handler.execute(
        {
            "command": "create",
            "path": path,
            "file_text": json.dumps(payload, indent=2, sort_keys=True) + "\n",
        }
    )
    return path


def extract_memory_tool_uses(content: Any) -> List[Dict[str, Any]]:
    """Return memory tool_use blocks from an assistant message content array."""
    blocks: List[Dict[str, Any]] = []
    if not isinstance(content, list):
        return blocks
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "tool_use" and str(item.get("name") or "") == "memory":
            blocks.append(item)
    return blocks


def build_memory_tool_results(
    handler: S3MemoryToolHandler, tool_uses: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for tool_use in tool_uses:
        tool_use_id = str(tool_use.get("id") or "").strip()
        tool_input = tool_use.get("input") if isinstance(tool_use.get("input"), dict) else {}
        content = handler.execute(tool_input)
        results.append(
            {
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": content,
            }
        )
    return results
