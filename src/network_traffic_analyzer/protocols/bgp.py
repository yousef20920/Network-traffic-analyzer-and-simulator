"""Simplified BGP UPDATE message parser used by the simulator."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import List, Optional


@dataclass(slots=True)
class BgpPathAttribute:
    """Represents a parsed BGP path attribute."""

    flags: int
    type_code: int
    value: object
    raw_value: bytes

    @property
    def name(self) -> str:
        mapping = {
            1: "ORIGIN",
            2: "AS_PATH",
            3: "NEXT_HOP",
            4: "MULTI_EXIT_DISC",
        }
        return mapping.get(self.type_code, f"ATTR_{self.type_code}")


@dataclass(slots=True)
class BgpUpdate:
    """Subset of information decoded from a BGP UPDATE message."""

    withdrawn_routes: List[str]
    path_attributes: List[BgpPathAttribute]
    nlri: List[str]

    def get_attribute(self, type_code: int) -> Optional[BgpPathAttribute]:
        for attribute in self.path_attributes:
            if attribute.type_code == type_code:
                return attribute
        return None

    @property
    def next_hop(self) -> Optional[str]:
        attribute = self.get_attribute(3)
        return attribute.value if attribute else None

    @property
    def as_path(self) -> List[int]:
        attribute = self.get_attribute(2)
        return attribute.value if attribute else []


class BgpParserError(ValueError):
    """Raised when the payload cannot be decoded as a BGP UPDATE."""


def parse_bgp_update(payload: bytes) -> BgpUpdate:
    """Parse a BGP UPDATE message.

    The simulator only produces IPv4 UPDATEs and therefore the parser focuses on
    a reduced portion of the RFC 4271 specification.  The implementation is kept
    deliberately small but is capable of handling real traffic captures with the
    same constraints.
    """

    if len(payload) < 23:
        raise BgpParserError("Payload too small for BGP header")

    marker = payload[:16]
    if marker != b"\xff" * 16:
        raise BgpParserError("Invalid marker in BGP header")

    length = struct.unpack("!H", payload[16:18])[0]
    if length != len(payload):
        raise BgpParserError("BGP length mismatch")

    message_type = payload[18]
    if message_type != 2:
        raise BgpParserError(f"Unsupported BGP message type {message_type}")

    offset = 19
    withdrawn_len = struct.unpack("!H", payload[offset : offset + 2])[0]
    offset += 2
    withdrawn_routes, offset = _parse_nlri(payload, offset, withdrawn_len)

    total_path_attr_len = struct.unpack("!H", payload[offset : offset + 2])[0]
    offset += 2
    path_attributes, offset = _parse_path_attributes(payload, offset, total_path_attr_len)

    nlri, offset = _parse_nlri(payload, offset, len(payload) - offset)
    if offset != len(payload):
        raise BgpParserError("Trailing bytes after NLRI parsing")

    return BgpUpdate(withdrawn_routes=withdrawn_routes, path_attributes=path_attributes, nlri=nlri)


def _parse_nlri(data: bytes, offset: int, length: int) -> tuple[List[str], int]:
    end = offset + length
    prefixes: List[str] = []
    while offset < end:
        prefix_length = data[offset]
        offset += 1
        byte_length = (prefix_length + 7) // 8
        prefix_bytes = data[offset : offset + byte_length]
        offset += byte_length
        # Pad to four bytes for IPv4 representation.
        padded = prefix_bytes.ljust(4, b"\x00")
        prefix = ipaddress.IPv4Address(padded)
        prefixes.append(f"{prefix}/{prefix_length}")
    return prefixes, offset


def _parse_path_attributes(data: bytes, offset: int, length: int) -> tuple[List[BgpPathAttribute], int]:
    end = offset + length
    attributes: List[BgpPathAttribute] = []
    while offset < end:
        if end - offset < 2:
            raise BgpParserError("Truncated path attribute header")
        flags = data[offset]
        type_code = data[offset + 1]
        offset += 2
        if flags & 0x10:  # extended length
            if end - offset < 2:
                raise BgpParserError("Truncated extended length")
            attr_len = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
        else:
            attr_len = data[offset]
            offset += 1
        if end - offset < attr_len:
            raise BgpParserError("Truncated path attribute payload")
        raw_value = data[offset : offset + attr_len]
        offset += attr_len
        value = _decode_attribute_value(type_code, raw_value)
        attributes.append(BgpPathAttribute(flags=flags, type_code=type_code, value=value, raw_value=raw_value))
    if offset != end:
        raise BgpParserError("Path attribute length mismatch")
    return attributes, offset


def _decode_attribute_value(type_code: int, raw_value: bytes) -> object:
    if type_code == 1:  # ORIGIN
        mapping = {0: "IGP", 1: "EGP", 2: "INCOMPLETE"}
        return mapping.get(raw_value[0], "UNKNOWN") if raw_value else "UNKNOWN"
    if type_code == 2:  # AS_PATH
        values: List[int] = []
        offset = 0
        while offset < len(raw_value):
            if len(raw_value) - offset < 2:
                raise BgpParserError("Malformed AS_PATH segment")
            segment_type = raw_value[offset]
            segment_length = raw_value[offset + 1]
            offset += 2
            if segment_type not in {1, 2}:
                raise BgpParserError(f"Unsupported AS_PATH segment type {segment_type}")
            for _ in range(segment_length):
                if len(raw_value) - offset < 2:
                    raise BgpParserError("Malformed AS_PATH value")
                values.append(struct.unpack("!H", raw_value[offset : offset + 2])[0])
                offset += 2
        return values
    if type_code == 3:  # NEXT_HOP
        if len(raw_value) != 4:
            raise BgpParserError("NEXT_HOP attribute must be 4 bytes")
        return str(ipaddress.IPv4Address(raw_value))
    if type_code == 4:  # MULTI_EXIT_DISC
        if len(raw_value) != 4:
            raise BgpParserError("MED attribute must be 4 bytes")
        return struct.unpack("!I", raw_value)[0]
    return raw_value
