# ELR v2 (draft section for DOC-F2CF625B7556)

> Drafted by ENC-TSK-P79 (T-B6, FR-B4-15..16). This file is the raw
> section text for the coordinator to apply to DOC-F2CF625B7556 through
> the docstore (documents.patch) -- it is not applied here; ELR does not
> call MCP/docstore tools. Covers: identity chain, TLS chain, environment
> profiles, the new elr-doc-digest / elr-doc-patch scripts, and every
> script's exit-code contract.

## Identity chain (ENC-TSK-P75, elr_lib/identity.py)

ELR resolves its own request identity in strict priority order, never
silently downgrading a partially-configured posture to a weaker one:

1. **`credential-bound`** -- an ENC-FTR-074 agent credential is present
   (`ENCELADUS_AGENT_CREDENTIAL` env var, or `~/.enceladus/credential.json`
   when that file exists AND is mode `0600`; any other mode is refused,
   never silently accepted). The credential drives a real
   `coordination(agent.register)` -> `coordination(agent.claim)`
   handshake that mints a live `ENC-SES-*` session id + `sci` for the
   run, so ELR writes carry a real governed session instead of a bare
   API key.
   - A `sci` that the server reports expired or revoked triggers exactly
     **one** re-claim + retry, never more (a second 403 after the
     re-claim is surfaced as a hard failure, not retried again).
   - `--keep-session` caches the resolved session to
     `~/.enceladus/session.json` (0600) for reuse across runs instead of
     retiring it on exit; without the flag, the session is retired at
     the end of the run.
   - A non-reclaimable failure mode (e.g. the credential itself is
     rejected, not just the session) is never retried.
2. **`internal-key`** -- no usable credential, but an internal API key is
   configured. Both `ENCELADUS_COORDINATION_INTERNAL_API_KEY` (existing
   convention, checked first) and the newer `ENCELADUS_INTERNAL_API_KEY`
   are accepted.
3. **`unknown`** -- neither is configured. Reads still work wherever the
   endpoint doesn't gate on identity (e.g. the health check). Every
   WRITE is refused **locally**, before any network call, with the
   remediation string `WRITE_REMEDIATION` ("provision an agent
   credential (ENC-FTR-074) or set ENCELADUS_INTERNAL_API_KEY").

## TLS resolution chain (ENC-TSK-P76, elr_lib/tls.py)

Every ELR HTTPS call goes through a **verifying** `ssl.SSLContext`
(`check_hostname=True`, `verify_mode=ssl.CERT_REQUIRED` always -- there
is no flag anywhere in ELR that disables certificate or hostname
verification). The CA bundle source is resolved in order, first match
wins:

1. `SSL_CERT_FILE` env var, if set and the path is readable and loads.
2. `certifi.where()`, if the `certifi` package is importable -- the ONE
   optional, guarded (`try/except ImportError`) third-party import
   anywhere in ELR's runtime file set (see AC-3 below).
3. The interpreter's own default verify paths, only if
   `ssl.create_default_context()` loads them without raising **and**
   the resulting store actually holds at least one CA cert
   (`cert_store_stats()['x509_ca'] > 0`); an empty default store is
   treated as "no CA bundle available", not a silent pass.
4. `"missing"` -- no CA bundle could be resolved anywhere. Callers MUST
   check `resolve_ca_bundle().source == SOURCE_MISSING` before opening a
   connection and fail fast with `REMEDIATION_MESSAGE`, instead of
   letting `urlopen` raise a raw `ssl.SSLCertVerificationError`.

## Environment profiles (ENC-TSK-P77, elr_lib/profiles.py)

Every ELR CLI's `--profile` flag selects which **deployed Enceladus
environment** ELR talks to (`prod` or `v4-gamma`), resolved via the
flag, else `ENCELADUS_PROFILE`, else `prod`. An unknown profile name
fails fast, listing the valid names. This is a distinct axis from
`elr_lib.config`'s existing transport profile (`internal` /
`mcp-http`, which picks the protocol/client shape) -- the two never
collide today because every script still hardcodes transport profile
`internal`. An environment profile supplies per-API base-URL
**defaults** only; an explicit `ENCELADUS_<API>_API_BASE` override
always wins.

## New scripts: elr-doc-digest and elr-doc-patch (ENC-TSK-P78)

**`elr_doc_digest.py DOC-ID [--docs-dir DIR] [--profile prod|v4-gamma]`**
Fetches `documents.manifest` (`{document_id, version, content_hash,
size_bytes, outline}`) and writes it plus a `fetched_at` timestamp to
`~/.enceladus/docs/{document_id}.digest.json`. This side file is the
**sole** source of `if_match` for `elr_doc_patch.py`'s optimistic-
concurrency writes. `elr_doc_get.py` writes the identical side-file
shape on every successful fetch, so either command keeps the cache
fresh. Exit 0 on success, nonzero otherwise; a digest is always
emitted on stdout.

**`elr_doc_patch.py --doc DOC-ID --anchor "..." --op {replace,append,prepend,delete} [--body-file FILE | stdin] [--dry-run]`**
Patches exactly ONE heading-anchored section of a governed document via
`POST /{document_id}/sections`, sending only
`{project_id, anchor, op, body?, if_match, governance_hash, ...}` --
never the full document body, regardless of document size (delta-only).
`elr_lib.plane_safety`'s pre-flight (the sentinel-identity hard gate)
runs unchanged before every real write. `--dry-run` renders a local
unified diff to **stderr** (the one exception to ELR's digest-only-on-
stdout contract) without touching the network.

Exit codes (elr_doc_patch.py):

| Code | Meaning |
| --- | --- |
| 0 | Success (write applied, or a clean `--dry-run` preview) |
| 1 | Generic refusal: local validation failure, plane-safety abort, unreachable/5xx/unexpected HTTP status, or missing local body cache needed for `--dry-run` |
| 2 | Precondition missing or stale -- run `elr_doc_digest.py --doc <ID>` (or `elr_doc_get.py <ID>`) first |
| 3 | 412 `CONTENT_HASH_MISMATCH` -- the side file is refreshed from the response envelope; `current_hash`/`current_version`/`recommended_next_actions` are reported |
| 5 | 404 `ANCHOR_NOT_FOUND` -- the server's outline is reported |
| 6 | 409 `ANCHOR_AMBIGUOUS` -- the server's candidate anchors are reported |

## Manifest distribution (ENC-TSK-O55 / ENC-TSK-P79)

`elr_sync.py generate-manifest` walks `tools/elr/` and hash-pins the
full runtime set: `elr_lib/*.py`, **`elr_lib/vendor/*.py`** (the
vendored outline/anchor-resolution modules `elr_lib.sections` imports
at load time -- added in ENC-TSK-P79; previously missing, which meant a
`pull`-ed install could import-fail on first use), every top-level
`elr_*.py` script, `elr_contracts.json`, and `README.md`.
`elr_lib/vendor/PINS.json` is deliberately excluded (re-vendoring
provenance metadata, not a runtime import). `pull --ref <40-hex sha>`
refuses to activate an install unless every listed file verifies
byte-for-byte; a corrupted file (proven in tests against
`elr_doc_patch.py` specifically) refuses with `409 hash-mismatch`
before any bytes land in `--dest`.

## Stdlib-only guarantee (ENC-TSK-P79 AC-3)

`certifi` is the **only** optional third-party import anywhere in
ELR's runtime file set, and it is always guarded
(`try: import certifi / except ImportError: certifi = None` in
`elr_lib/tls.py`). `tools/elr/tests/test_stdlib_only.py` enforces this
two ways: (1) every runtime module imports cleanly with `certifi`
forced unimportable via a test-only meta-path finder, and (2) an AST
scan of every runtime `.py` file confirms no other file references
`certifi` at all, and `elr_lib/tls.py`'s reference sits inside a
`try/except ImportError`.

## Fresh-install verification (coordinator-owned live part, ENC-TSK-P78/P79 AC-4)

The commands below are safe to run from any machine with no prior ELR
state (`~/.enceladus` does not need to exist) and make no writes
outside `--dest`:

```bash
# Prove the CLIs load and parse with zero pre-existing HOME state.
HOME=$(mktemp -d) python3 tools/elr/elr_sync.py --help
HOME=$(mktemp -d) python3 tools/elr/elr_sync.py generate-manifest --help
HOME=$(mktemp -d) python3 tools/elr/elr_smoke.py --help

# Real fresh-install pull + live multi-profile smoke (coordinator-run,
# needs network + real credentials/keys -- not exercised by ENC-TSK-P79,
# which is code/tests-only per brief_common.md):
HOME=$(mktemp -d) python3 tools/elr/elr_sync.py pull --ref <40-hex-sha> --dest ~/.enceladus/elr/bin
HOME=$(mktemp -d) python3 ~/.enceladus/elr/bin/elr_smoke.py --all-profiles
```

`elr_smoke.py` has no offline/dry-run mode (it is, by design, one
cheap live governed READ per profile) -- the `--help` invocation above
is the closest available offline verification that the fresh-HOME
install path itself is sound; the actual `--all-profiles` live run
against prod and v4-gamma is the coordinator-owned evidence capture.
