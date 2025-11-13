from __future__ import annotations

from network_traffic_analyzer.dashboard import DashboardData
from network_traffic_analyzer.metrics import TrafficMetrics
from network_traffic_analyzer.packets import Packet
from network_traffic_analyzer.topology import NetworkTopology

from .conftest import build_bgp_update, build_ospf_router_lsa


def _sample_packets() -> list[Packet]:
    bgp_packet = Packet(
        timestamp=1.0,
        src_ip="203.0.113.1",
        dst_ip="198.51.100.1",
        transport_protocol="TCP",
        payload_protocol="BGP",
        length=128,
        payload=build_bgp_update(prefix="10.1.0.0/24", next_hop="198.51.100.1"),
        latency_ms=95.0,
        throughput_mbps=80.0,
    )
    ospf_packet = Packet(
        timestamp=1.5,
        src_ip="198.51.100.1",
        dst_ip="224.0.0.5",
        transport_protocol="IP",
        payload_protocol="OSPF",
        length=96,
        payload=build_ospf_router_lsa(
            advertising_router="198.51.100.1", neighbor="198.51.100.2", metric=5
        ),
        latency_ms=20.0,
        throughput_mbps=120.0,
    )
    return [bgp_packet, ospf_packet]


def test_topology_and_dashboard() -> None:
    packets = _sample_packets()
    topology = NetworkTopology()
    metrics = TrafficMetrics()
    for packet in packets:
        topology.ingest_packet(packet)
        metrics.record_packet(packet)

    assert topology.describe_prefix("10.1.0.0/24") == "198.51.100.1"
    path = topology.shortest_path("198.51.100.1", "198.51.100.2")
    assert path == ["198.51.100.1", "198.51.100.2"]

    dashboard = DashboardData(metrics=metrics, topology=topology)
    summary = dashboard.summary()
    assert "198.51.100.1" in summary["nodes"]
    assert summary["average_latency_ms"]["203.0.113.1->198.51.100.1"] == 95.0
    markdown = dashboard.to_markdown()
    assert "Network Traffic Dashboard" in markdown
