"""Network topology construction using BGP and OSPF advertisements."""

from __future__ import annotations

import heapq
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .packets import Packet
from .protocols.bgp import BgpUpdate, parse_bgp_update
from .protocols.ospf import OspfRouterLsa, parse_ospf_lsas

Link = Tuple[str, str]


@dataclass
class LinkMetadata:
    metric: float = 1.0
    protocols: Set[str] = field(default_factory=set)


class NetworkTopology:
    """Incrementally build a topology graph from captured packets."""

    def __init__(self) -> None:
        self.nodes: Set[str] = set()
        self.links: Dict[Link, LinkMetadata] = defaultdict(LinkMetadata)
        self.prefix_origins: Dict[str, str] = {}

    def add_link(self, src: str, dst: str, *, metric: float, protocol: str) -> None:
        self.nodes.update({src, dst})
        metadata = self.links[(src, dst)]
        metadata.metric = min(metadata.metric, metric) if metadata.protocols else metric
        metadata.protocols.add(protocol)

    def add_prefix_origin(self, prefix: str, next_hop: Optional[str]) -> None:
        if next_hop is not None:
            self.prefix_origins[prefix] = next_hop

    def apply_bgp_update(self, source_router: str, update: BgpUpdate) -> None:
        self.nodes.add(source_router)
        if update.next_hop:
            self.add_link(source_router, update.next_hop, metric=1.0, protocol="BGP")
        for prefix in update.nlri:
            self.add_prefix_origin(prefix, update.next_hop)

    def apply_ospf_lsa(self, lsa: OspfRouterLsa) -> None:
        self.nodes.add(lsa.advertising_router)
        for link in lsa.links:
            neighbor = link.link_id
            cost = max(1, link.metric)
            self.add_link(lsa.advertising_router, neighbor, metric=float(cost), protocol="OSPF")

    def ingest_packet(self, packet: Packet) -> None:
        if packet.payload_protocol == "BGP":
            update = parse_bgp_update(packet.payload)
            self.apply_bgp_update(packet.src_ip, update)
        elif packet.payload_protocol == "OSPF":
            for lsa in parse_ospf_lsas(packet.payload):
                self.apply_ospf_lsa(lsa)

    def ingest(self, packets: Iterable[Packet]) -> None:
        for packet in packets:
            self.ingest_packet(packet)

    def adjacency(self) -> Dict[str, Set[str]]:
        neighbours: Dict[str, Set[str]] = defaultdict(set)
        for (src, dst), metadata in self.links.items():
            neighbours[src].add(dst)
        return neighbours

    def shortest_path(self, src: str, dst: str) -> Optional[List[str]]:
        if src not in self.nodes or dst not in self.nodes:
            return None
        queue: list[tuple[float, str, List[str]]] = [(0.0, src, [src])]
        visited: Dict[str, float] = {src: 0.0}
        while queue:
            cost, node, path = heapq.heappop(queue)
            if node == dst:
                return path
            for neighbour, metadata in self._neighbours_with_metadata(node):
                new_cost = cost + metadata.metric
                if neighbour not in visited or new_cost < visited[neighbour]:
                    visited[neighbour] = new_cost
                    heapq.heappush(queue, (new_cost, neighbour, path + [neighbour]))
        return None

    def _neighbours_with_metadata(self, node: str) -> Iterable[tuple[str, LinkMetadata]]:
        for (src, dst), metadata in self.links.items():
            if src == node:
                yield dst, metadata

    def describe_prefix(self, prefix: str) -> Optional[str]:
        return self.prefix_origins.get(prefix)
