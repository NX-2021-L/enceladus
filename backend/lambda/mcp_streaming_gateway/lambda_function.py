"""ENC-TSK-L10: build-discovery marker for mcp_streaming_gateway.

This Lambda runs under the AWS Lambda Web Adapter (see run.sh), which
replaces the standard runtime handler dispatch entirely (AWS_LAMBDA_EXEC_WRAPPER
bypasses this module at invoke time) -- the real entry point is asgi_app.py's
Starlette `application`, served by uvicorn as a persistent process.

This file exists only so `.github/workflows/_build.yml`'s discovery step
(`find backend/lambda -maxdepth 2 -name lambda_function.py`) picks up this
directory and packages it. If this ever executes for real, the adapter isn't
configured correctly.
"""


def lambda_handler(event, context):
    raise RuntimeError(
        "mcp_streaming_gateway.lambda_function.lambda_handler was invoked directly -- "
        "the AWS Lambda Web Adapter (AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap) should have "
        "intercepted this invocation and routed it to asgi_app.application instead. "
        "Check the function's environment variables and layer configuration."
    )
