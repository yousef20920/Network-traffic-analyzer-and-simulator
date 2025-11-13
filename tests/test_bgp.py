from __future__ import annotations

from network_traffic_analyzer.protocols.bgp import BgpParserError, parse_bgp_update
from .conftest import build_bgp_update


def test_parse_bgp_update() -> None:
    payload = build_bgp_update()
    update = parse_bgp_update(payload)
    assert update.next_hop == "192.0.2.1"
    assert update.as_path == [65001, 65002]
    assert update.nlri == ["10.0.0.0/24"]


def test_invalid_marker_raises() -> None:
    payload = bytearray(build_bgp_update())
    payload[0] = 0x00
    try:
        parse_bgp_update(bytes(payload))
    except BgpParserError as exc:
        assert "marker" in str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected BgpParserError")
