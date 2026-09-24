"""Gen2 build entrypoint for enceladus-mcp-code (ENC-TSK-K11).

The deployed Lambda handler remains ``server.lambda_handler`` (see
infrastructure/lambda-manifests/enceladus-mcp-code.json). This shim exists so
``_build.yml`` discovers ``mcp_code`` via ``lambda_function.py`` and packages
``tools/enceladus-mcp-server/`` runtime modules into the artifact zip.
"""

from server import lambda_handler  # noqa: F401

__all__ = ["lambda_handler"]
