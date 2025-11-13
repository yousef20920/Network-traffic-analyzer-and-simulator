from __future__ import annotations
from __future__ import annotations

from network_traffic_analyzer.protocols.ospf import OspfParserError, parse_ospf_lsas
from .conftest import build_ospf_router_lsa


def test_parse_router_lsa() -> None:
    payload = build_ospf_router_lsa()
    lsas = parse_ospf_lsas(payload)
    assert len(lsas) == 1
    lsa = lsas[0]
    assert lsa.advertising_router == "192.0.2.1"
    assert lsa.links[0].link_id == "192.0.2.2"
    assert lsa.links[0].metric == 10


def test_ospf_wrong_type() -> None:
    payload = bytearray(build_ospf_router_lsa())
    payload[1] = 1  # invalid packet type
    try:
        parse_ospf_lsas(bytes(payload))
    except OspfParserError as exc:
        assert "packet type" in str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected OspfParserError")
