"""OSPF Link State Advertisement parser."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import List


@dataclass(slots=True)
class OspfRouterLink:
    """Representation of a link contained within a Router-LSA."""

    link_id: str
    link_data: str
    link_type: int
    metric: int


@dataclass(slots=True)
class OspfRouterLsa:
    """Subset of decoded information from a Router-LSA."""

    advertising_router: str
    link_state_id: str
    links: List[OspfRouterLink]


class OspfParserError(ValueError):
    """Raised when the payload cannot be decoded as an OSPF LS Update."""


def parse_ospf_lsas(payload: bytes) -> List[OspfRouterLsa]:
    if len(payload) < 28:
        raise OspfParserError("Payload too small for OSPF header")

    version, packet_type, packet_length = struct.unpack("!BBH", payload[:4])
    if version != 2:
        raise OspfParserError(f"Unsupported OSPF version {version}")
    if packet_type != 4:
        raise OspfParserError(f"Unsupported OSPF packet type {packet_type}")
    if packet_length != len(payload):
        raise OspfParserError("OSPF length mismatch")

    lsa_count = struct.unpack("!I", payload[24:28])[0]
    offset = 28
    lsas: List[OspfRouterLsa] = []

    for _ in range(lsa_count):
        if len(payload) - offset < 20:
            raise OspfParserError("Truncated LSA header")
        lsa_header = payload[offset : offset + 20]
        offset += 20
        _ls_age, _options, ls_type = struct.unpack("!HBB", lsa_header[:4])
        link_state_id = str(ipaddress.IPv4Address(lsa_header[4:8]))
        advertising_router = str(ipaddress.IPv4Address(lsa_header[8:12]))
        _seq_num = struct.unpack("!I", lsa_header[12:16])[0]
        lsa_length = struct.unpack("!H", lsa_header[18:20])[0]
        if len(payload) - offset < lsa_length - 20:
            raise OspfParserError("Truncated LSA body")
        lsa_body = payload[offset : offset + (lsa_length - 20)]
        offset += lsa_length - 20

        if ls_type != 1:
            # Only Router-LSAs are produced by the simulator. Skip others.
            continue

        if len(lsa_body) < 4:
            raise OspfParserError("Router-LSA body too small")
        _flags = lsa_body[0]
        num_links = struct.unpack("!H", lsa_body[2:4])[0]
        link_offset = 4
        links: List[OspfRouterLink] = []
        for _ in range(num_links):
            if len(lsa_body) - link_offset < 12:
                raise OspfParserError("Truncated Router-LSA link")
            link_id = str(ipaddress.IPv4Address(lsa_body[link_offset : link_offset + 4]))
            link_data = str(ipaddress.IPv4Address(lsa_body[link_offset + 4 : link_offset + 8]))
            link_type = lsa_body[link_offset + 8]
            tos_count = lsa_body[link_offset + 9]
            metric = struct.unpack("!H", lsa_body[link_offset + 10 : link_offset + 12])[0]
            link_offset += 12 + (tos_count * 4)
            links.append(
                OspfRouterLink(
                    link_id=link_id,
                    link_data=link_data,
                    link_type=link_type,
                    metric=metric,
                )
            )
        lsas.append(
            OspfRouterLsa(
                advertising_router=advertising_router,
                link_state_id=link_state_id,
                links=links,
            )
        )

    return lsas
