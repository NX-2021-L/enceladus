"""DVP-TSK-968: the bundled recipe_caps snapshot (shipped in the tracker_mutation zip) must equal the parity snapshots."""
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
PARITY = HERE.parent.parent.parent / "tools" / "enceladus-mcp-server" / "parity"


def test_bundled_caps_match_parity_snapshots():
    bundled = HERE / "recipe_caps"
    assert (bundled / "caps.json").read_bytes() == (PARITY / "caps.json").read_bytes()
    for src in sorted((PARITY / "surfaces").glob("*.caps.json")):
        assert (bundled / "surfaces" / src.name).read_bytes() == src.read_bytes(), src.name
