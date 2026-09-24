"""Gen2 build entrypoint for enceladus-mcp-streamable (ENC-TSK-K12).

The deployed Lambda handler remains ``server.lambda_handler`` (see
infrastructure/lambda-manifests/enceladus-mcp-streamable.json if present).
This shim exists so ``_build.yml`` discovers ``mcp_streamable`` via
``lambda_function.py`` and packages ``tools/enceladus-mcp-server/`` runtime
modules into the artifact zip (mcp.jreese.net Function URL path).
"""

from server import lambda_handler  # noqa: F401

__all__ = ["lambda_handler"]
