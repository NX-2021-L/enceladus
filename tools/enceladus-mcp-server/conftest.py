"""Test defaults for the MCP server suite.

ENC-TSK-S29-0A: the per-step governance probe in execute would reach the governance API (network)
for tests that load the real server with fake tool handlers. It is off here; the S29-0A tests
install their own scripted probe on RUNTIME.
"""
import os

os.environ.setdefault("ENCELADUS_EXECUTE_GOVERNANCE_PROBE", "off")
