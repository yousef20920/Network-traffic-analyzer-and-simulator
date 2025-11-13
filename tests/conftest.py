from __future__ import annotations

import struct


def build_bgp_update(prefix: str = "10.0.0.0/24", next_hop: str = "192.0.2.1") -> bytes:
    import ipaddress

    marker = b"\xff" * 16
    message_type = 2

    withdrawn_routes = b"\x00\x00"

    origin_attr = bytes([0x40, 1, 1, 0])

    as_path_value = struct.pack("!BBHH", 2, 2, 65001, 65002)
    as_path_attr = bytes([0x40, 2, len(as_path_value)]) + as_path_value

    next_hop_attr = bytes([0x40, 3, 4]) + ipaddress.IPv4Address(next_hop).packed

    med_attr = bytes([0x80, 4, 4]) + struct.pack("!I", 25)

    path_attributes = origin_attr + as_path_attr + next_hop_attr + med_attr
    total_path_len = struct.pack("!H", len(path_attributes))

    prefix_ip, prefix_length = prefix.split("/")
    prefix_length = int(prefix_length)
    prefix_bytes = ipaddress.IPv4Address(prefix_ip).packed[: (prefix_length + 7) // 8]
    nlri = bytes([prefix_length]) + prefix_bytes

    length = 19 + len(withdrawn_routes) + 2 + len(path_attributes) + len(nlri)
    header = marker + struct.pack("!HB", length, message_type)

    return header + withdrawn_routes + total_path_len + path_attributes + nlri


def build_ospf_router_lsa(
    advertising_router: str = "192.0.2.1",
    neighbor: str = "192.0.2.2",
    metric: int = 10,
) -> bytes:
    import ipaddress

    version = 2
    packet_type = 4

    lsa_body = bytes([0, 0]) + struct.pack("!H", 1)
    lsa_body += ipaddress.IPv4Address(neighbor).packed
    lsa_body += ipaddress.IPv4Address("255.255.255.0").packed
    lsa_body += bytes([1, 0])
    lsa_body += struct.pack("!H", metric)

    lsa_length = 20 + len(lsa_body)
    lsa_header = struct.pack("!HBB", 1, 0, 1)
    lsa_header += ipaddress.IPv4Address(neighbor).packed
    lsa_header += ipaddress.IPv4Address(advertising_router).packed
    lsa_header += struct.pack("!I", 0x80000001)
    lsa_header += struct.pack("!H", 0)
    lsa_header += struct.pack("!H", lsa_length)

    ls_update_body = struct.pack("!I", 1) + lsa_header + lsa_body

    packet_length = 24 + len(ls_update_body)
    ospf_header = struct.pack("!BBH", version, packet_type, packet_length)
    ospf_header += ipaddress.IPv4Address(advertising_router).packed
    ospf_header += ipaddress.IPv4Address("0.0.0.0").packed
    ospf_header += struct.pack("!H", 0)
    ospf_header += struct.pack("!H", 0)
    ospf_header += b"\x00" * 8

    return ospf_header + ls_update_body
