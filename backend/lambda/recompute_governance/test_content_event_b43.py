"""DVP-TSK-B43 (isolation W4l): prod content bucket governance/live events drive each plane's recompute (no AWS).

governance/ is ONE shared corpus in the PROD content bucket (DOC-EF4BC758CCC9). That bucket sends its events to
EventBridge (W2 stack, prod only) and each plane's 02-compute owns a rule that invokes its OWN recompute. The rule's
InputTransformer rebuilds the S3-notification shape the handler already parses; these tests render that template
from the template file the way EventBridge does and feed the result to the handler.
"""

import json
import os
import re
import sys
from unittest import mock

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(HERE, "..", "shared_layer", "python"))

import lambda_function as mod  # noqa: E402

CFN = os.path.join(HERE, "..", "..", "..", "infrastructure", "cloudformation")


def _block(text, name):
    """The resource's body with comment lines dropped."""
    m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n|\Z)", text)
    assert m, name
    return "".join(ln for ln in m.group(1).splitlines(True) if not ln.lstrip().startswith("#"))


@pytest.fixture(scope="module")
def rule():
    with open(os.path.join(CFN, "02-compute.yaml"), encoding="utf-8") as fh:
        text = fh.read()
    return _block(text, "RecomputeGovernanceContentEventRule"), _block(text, "RecomputeGovernanceContentEventPermission")


def _eventbridge_object_created(key, sequencer="0065F1A2B3C4D5E6F7", version_id="3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY"):
    return {
        "version": "0", "detail-type": "Object Created", "source": "aws.s3", "region": "us-west-2",
        "resources": ["arn:aws:s3:::enceladus-content-356364570033-us-west-2"],
        "detail": {
            "version": "0", "bucket": {"name": "enceladus-content-356364570033-us-west-2"},
            "object": {"key": key, "size": 12, "etag": "e", "version-id": version_id, "sequencer": sequencer},
            "request-id": "r", "requester": "356364570033", "reason": "PutObject",
        },
    }


def _render(rule_text, event):
    """EventBridge's InputTransformer: each unquoted <var> becomes the JSON value at its InputPathsMap path."""
    paths = dict(re.findall(r"^\s+(\w+): \$\.([\w.-]+)$", rule_text.split("InputPathsMap:", 1)[1].split("InputTemplate:")[0],
                            re.M))
    template = re.search(r"InputTemplate: '(.*)'$", rule_text, re.M).group(1)

    def value(path):
        node = event
        for part in path.split("."):
            node = node[part]
        return node

    return json.loads(re.sub(r"<(\w+)>", lambda m: json.dumps(value(paths[m.group(1)])), template))


def test_rule_matches_governance_live_in_the_shared_prod_bucket_only(rule):
    b, _ = rule
    assert "source:\n          - aws.s3" in b and "- Object Created" in b
    assert '- !Sub "enceladus-content-${AWS::AccountId}-${AWS::Region}"' in b  # no ${EnvironmentSuffix}: one corpus
    assert "- prefix: governance/live/" in b
    assert "State: ENABLED" in b


def test_each_plane_invokes_its_own_recompute(rule):
    b, perm = rule
    assert 'Name: !Sub "devops-recompute-governance-content${EnvironmentSuffix}"' in b
    assert "Arn: !GetAtt RecomputeGovernanceFunction.Arn" in b
    assert "FunctionName: !Ref RecomputeGovernanceFunction" in perm
    assert "Principal: events.amazonaws.com" in perm
    assert "SourceArn: !GetAtt RecomputeGovernanceContentEventRule.Arn" in perm


def test_rendered_payload_is_the_s3_shape_the_handler_parses(rule):
    payload = _render(rule[0], _eventbridge_object_created("governance/live/agents/primer.md"))
    record = mod._extract_s3_record(payload)
    assert record["s3"]["object"] == {"key": "governance/live/agents/primer.md", "sequencer": "0065F1A2B3C4D5E6F7",
                                      "versionId": "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY"}


def test_handler_recomputes_for_a_canonical_key(rule):
    payload = _render(rule[0], _eventbridge_object_created("governance/live/agents.md"))
    with mock.patch.object(mod, "_read_current_record", return_value=None), \
            mock.patch.object(mod, "_list_canonical_files", return_value=[]) as listed:
        mod.handler(payload, None)
    listed.assert_called_once()  # past the canonical-key and dedup gates; [] then refuses to write an empty hash


def test_handler_dedups_a_repeated_sequencer(rule):
    payload = _render(rule[0], _eventbridge_object_created("governance/live/agents.md", sequencer="SEQ1"))
    current = {"generation": 4, "cas_version": 4, "source_event": {"s3_sequencer": "SEQ1"}}
    with mock.patch.object(mod, "_read_current_record", return_value=current), \
            mock.patch.object(mod, "_list_canonical_files") as listed:
        mod.handler(payload, None)
    listed.assert_not_called()


def test_handler_ignores_non_canonical_governance_keys(rule):
    payload = _render(rule[0], _eventbridge_object_created("governance/live/governance_data_dictionary.json"))
    with mock.patch.object(mod, "_read_current_record") as read:
        mod.handler(payload, None)
    read.assert_not_called()


def test_only_the_prod_content_bucket_sends_events_to_eventbridge():
    with open(os.path.join(CFN, "isolation", "w2-content-storage.yaml"), encoding="utf-8") as fh:
        b = _block(fh.read(), "ContentBucket")
    assert re.search(r"NotificationConfiguration: !If\n\s+- IsProduction\n\s+- EventBridgeConfiguration:\n"
                     r"\s+EventBridgeEnabled: true\n\s+- !Ref AWS::NoValue\n", b)
