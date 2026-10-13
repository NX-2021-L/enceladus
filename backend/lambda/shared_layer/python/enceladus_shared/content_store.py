"""enceladus_shared.content_store — dual-path S3 access for the Enceladus content move (isolation W4).

DOC-EF4BC758CCC9 (io approved D1-D7, 2026-10-12) moves every Enceladus prefix out of the shared public bucket
(s3://jreese-net, gamma under ``gamma/``) into the per-environment content bucket
(``enceladus-content${suffix}-<account>-<region>``, SSE-KMS, private). This module is the single code path every
Lambda uses for those prefixes, so a function moves by flipping one environment variable, never by editing its
call sites again:

    CONTENT_STORE_MODE = legacy   read/write the legacy bucket only (today's behaviour; the default)
                       = dual     write BOTH (content first, then legacy; conditional puts legacy first); read content,
                                  fall back to legacy on a miss
                       = content  read/write the content bucket only

Keys are the legacy keys. In gamma the legacy key carries the ``gamma/`` prefix (S3_ENV_PREFIX); the content bucket
is per environment, so that prefix is dropped there. ``ContentStore.from_env`` reads:

    CONTENT_STORE_MODE        legacy | dual | content (default legacy)
    CONTENT_STORE_READ        auto (default) | legacy. In dual mode, legacy keeps reads on the legacy bucket while writes go
                              to both: the writer-first phase, so a function that rewrites what it reads never regenerates
                              from a stale content snapshot (DVP-TSK-B09).
    CONTENT_BUCKET            enceladus-content${suffix}-<account>-<region>
    LEGACY_BUCKET             default: S3_BUCKET, else jreese-net
    S3_ENV_PREFIX             legacy-only key prefix (gamma: "gamma/"), stripped for the content bucket

Shipping: canonical copy here (digest-pinned in MODULE_DIGESTS.json). A migrating function vendors an identical
copy next to its handler (tools/isolation/sync_content_store.py), and a CI guard asserts every copy matches, so
there is no layer republish or fleet-wide layer pin change.

Part of DVP-TSK-A78 (isolation W4).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

MODES = ("legacy", "dual", "content")
READ_MODES = ("auto", "legacy")
DEFAULT_LEGACY_BUCKET = "jreese-net"


class ContentStoreConfigError(ValueError):
    pass


def _error_code(exc: Exception) -> str:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return str((resp.get("Error") or {}).get("Code", ""))
    return ""


def _is_precondition_failed(exc: Exception) -> bool:
    return _error_code(exc) in ("PreconditionFailed", "412")


_CONDITIONAL_KWARGS = ("IfNoneMatch", "IfMatch")


def _is_missing(exc: Exception) -> bool:
    code = ""
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = str((resp.get("Error") or {}).get("Code", ""))
    name = type(exc).__name__
    return code in ("NoSuchKey", "404", "NotFound") or name in ("NoSuchKey",)


class ContentStore:
    """Mode-aware wrapper over one boto3 S3 client for the Enceladus content prefixes."""

    def __init__(self, s3_client: Any, *, mode: str = "legacy", content_bucket: str = "",
                 legacy_bucket: str = DEFAULT_LEGACY_BUCKET, legacy_key_prefix: str = "", read_mode: str = "auto") -> None:
        if mode not in MODES:
            raise ContentStoreConfigError(f"CONTENT_STORE_MODE must be one of {MODES}, got {mode!r}")
        if read_mode not in READ_MODES:
            raise ContentStoreConfigError(f"CONTENT_STORE_READ must be one of {READ_MODES}, got {read_mode!r}")
        if read_mode == "legacy" and mode == "content":
            raise ContentStoreConfigError("CONTENT_STORE_READ=legacy contradicts CONTENT_STORE_MODE=content")
        if mode != "legacy" and not content_bucket:
            raise ContentStoreConfigError(f"CONTENT_STORE_MODE={mode} needs CONTENT_BUCKET")
        self.s3 = s3_client
        self.mode = mode
        self.content_bucket = content_bucket
        self.legacy_bucket = legacy_bucket or DEFAULT_LEGACY_BUCKET
        self.legacy_key_prefix = legacy_key_prefix or ""
        self.read_mode = read_mode

    @classmethod
    def from_env(cls, s3_client: Any, env: Optional[Dict[str, str]] = None) -> "ContentStore":
        e = os.environ if env is None else env
        return cls(
            s3_client,
            mode=(e.get("CONTENT_STORE_MODE") or "legacy").strip().lower(),
            content_bucket=(e.get("CONTENT_BUCKET") or "").strip(),
            legacy_bucket=(e.get("LEGACY_BUCKET") or e.get("S3_BUCKET") or DEFAULT_LEGACY_BUCKET).strip(),
            legacy_key_prefix=e.get("S3_ENV_PREFIX", ""),
            read_mode=(e.get("CONTENT_STORE_READ") or "auto").strip().lower(),
        )

    # -- key mapping -------------------------------------------------------------------------------------------
    def content_key(self, legacy_key: str) -> str:
        """The content-bucket key for a legacy key (drops the legacy-only env prefix)."""
        p = self.legacy_key_prefix
        return legacy_key[len(p):] if p and legacy_key.startswith(p) else legacy_key

    def _targets_for_write(self, key: str) -> List[tuple]:
        if self.mode == "legacy":
            return [(self.legacy_bucket, key)]
        if self.mode == "content":
            return [(self.content_bucket, self.content_key(key))]
        return [(self.content_bucket, self.content_key(key)), (self.legacy_bucket, key)]

    def _read_order(self, key: str) -> List[tuple]:
        if self.mode == "legacy" or self.read_mode == "legacy":
            return [(self.legacy_bucket, key)]
        if self.mode == "content":
            return [(self.content_bucket, self.content_key(key))]
        return [(self.content_bucket, self.content_key(key)), (self.legacy_bucket, key)]

    # -- reads -------------------------------------------------------------------------------------------------
    def get_object(self, key: str, **kwargs: Any) -> Dict[str, Any]:
        order = self._read_order(key)
        last: Optional[Exception] = None
        for i, (bucket, k) in enumerate(order):
            try:
                return self.s3.get_object(Bucket=bucket, Key=k, **kwargs)
            except Exception as exc:  # fall back only on a miss, and only in dual mode
                if i + 1 < len(order) and _is_missing(exc):
                    last = exc
                    continue
                raise
        raise last  # pragma: no cover (loop always returns or raises)

    def head_object(self, key: str, **kwargs: Any) -> Dict[str, Any]:
        order = self._read_order(key)
        for i, (bucket, k) in enumerate(order):
            try:
                return self.s3.head_object(Bucket=bucket, Key=k, **kwargs)
            except Exception as exc:
                if i + 1 < len(order) and _is_missing(exc):
                    continue
                raise
        raise ContentStoreConfigError("unreachable")  # pragma: no cover

    def read_bytes(self, key: str) -> bytes:
        return self.get_object(key)["Body"].read()

    def list_keys(self, prefix: str, max_keys: Optional[int] = None) -> List[str]:
        """Legacy-form keys under ``prefix`` (a legacy-form prefix). Dual mode merges both buckets."""
        seen: Dict[str, None] = {}
        for bucket, p, to_legacy in self._list_sources(prefix):
            pag = self.s3.get_paginator("list_objects_v2")
            for page in pag.paginate(Bucket=bucket, Prefix=p):
                for o in page.get("Contents", []):
                    seen.setdefault(to_legacy(o["Key"]), None)
                    if max_keys and len(seen) >= max_keys:
                        return list(seen)[:max_keys]
        return list(seen)

    def _list_sources(self, prefix: str):
        legacy = (self.legacy_bucket, prefix, lambda k: k)
        content = (self.content_bucket, self.content_key(prefix), lambda k: self.legacy_key_prefix + k)
        if self.read_mode == "legacy":
            return [legacy]
        return {"legacy": [legacy], "content": [content], "dual": [content, legacy]}[self.mode]

    # -- writes ------------------------------------------------------------------------------------------------
    def put_object(self, key: str, body: Any, **kwargs: Any) -> Dict[str, Any]:
        """Write to every target for the mode; the FIRST target's response is returned (content in dual).

        A conditional put (IfNoneMatch / IfMatch) in dual mode is the exception (DVP-TSK-B14): the legacy bucket is
        written FIRST and arbitrates. If it raises (e.g. PreconditionFailed because the immutable object exists) the
        error propagates and the content bucket is never touched. Only then is the content bucket written; a
        PreconditionFailed there is swallowed, because the W3 snapshot already holds that immutable object. The legacy
        response is returned in this case.
        """
        targets = self._targets_for_write(key)
        if self.mode == "dual" and any(c in kwargs for c in _CONDITIONAL_KWARGS):
            legacy_bucket, legacy_k = targets[1]
            legacy_resp = self.s3.put_object(Bucket=legacy_bucket, Key=legacy_k, Body=body, **dict(kwargs))
            content_bucket, content_k = targets[0]
            try:
                self.s3.put_object(Bucket=content_bucket, Key=content_k, Body=body, **self._content_kwargs(kwargs))
            except Exception as exc:
                if not _is_precondition_failed(exc):
                    raise
            return legacy_resp
        responses = []
        for bucket, k in targets:
            kw = self._content_kwargs(kwargs) if bucket == self.content_bucket else dict(kwargs)
            responses.append(self.s3.put_object(Bucket=bucket, Key=k, Body=body, **kw))
        return responses[0]

    @staticmethod
    def _content_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """The content bucket encrypts with its own key by default and denies other keys / SSE-S3."""
        kw = dict(kwargs)
        kw.pop("ServerSideEncryption", None)
        kw.pop("SSEKMSKeyId", None)
        kw.pop("ACL", None)
        return kw

    def copy_object(self, src_key: str, dest_key: str, **kwargs: Any) -> Dict[str, Any]:
        """Server-side copy to every write target for ``dest_key``; both keys are legacy-form. First response returned.

        Content target: the source is the content copy of ``src_key``. In dual mode a miss there (an object created
        after the W3 snapshot exists only in legacy) retries once from the legacy source into the same content dest.
        Legacy target: the source is the legacy copy of ``src_key``.
        """
        responses = []
        for bucket, k in self._targets_for_write(dest_key):
            if bucket == self.content_bucket:
                kw = self._content_kwargs(kwargs)
                try:
                    resp = self.s3.copy_object(
                        Bucket=bucket, Key=k, CopySource={"Bucket": self.content_bucket, "Key": self.content_key(src_key)}, **kw)
                except Exception as exc:
                    if self.mode != "dual" or not (_is_missing(exc) or _error_code(exc) in ("NoSuchKey", "404")):
                        raise
                    resp = self.s3.copy_object(
                        Bucket=bucket, Key=k, CopySource={"Bucket": self.legacy_bucket, "Key": src_key}, **kw)
            else:
                resp = self.s3.copy_object(
                    Bucket=bucket, Key=k, CopySource={"Bucket": self.legacy_bucket, "Key": src_key}, **dict(kwargs))
            responses.append(resp)
        return responses[0]

    def upload_file(self, local_path: str, key: str, extra_args: Optional[Dict[str, Any]] = None) -> None:
        """boto3 managed upload (multipart for large files) to every write target for the mode."""
        for bucket, k in self._targets_for_write(key):
            args = dict(extra_args or {})
            if bucket == self.content_bucket:
                for drop in ("ServerSideEncryption", "SSEKMSKeyId", "ACL"):
                    args.pop(drop, None)
            self.s3.upload_file(local_path, bucket, k, ExtraArgs=args or None)

    def delete_object(self, key: str) -> None:
        for bucket, k in self._targets_for_write(key):
            self.s3.delete_object(Bucket=bucket, Key=k)

    def presigned_get_url(self, key: str, expires_in: int = 3600) -> str:
        """Presigned GET from the bucket that holds the object (dual: content if present, else legacy)."""
        order = self._read_order(key)
        bucket, k = order[0]
        if len(order) > 1:
            try:
                self.s3.head_object(Bucket=bucket, Key=k)
            except Exception as exc:
                if not _is_missing(exc):
                    raise
                bucket, k = order[1]
        return self.s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": k}, ExpiresIn=expires_in)
