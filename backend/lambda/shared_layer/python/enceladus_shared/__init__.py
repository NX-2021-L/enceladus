"""enceladus_shared — Shared utilities for Enceladus Lambda functions.

Provides:
    - Cognito JWT authentication (cookie-based)
    - DynamoDB client singleton
    - HTTP response helpers with CORS
    - DynamoDB serialization/deserialization

Part of ENC-TSK-525: Extract shared Lambda layer.
"""

__version__ = "1.0.0"
