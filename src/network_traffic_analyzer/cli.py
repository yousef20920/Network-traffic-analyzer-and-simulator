"""Command line entry point for the analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List

from .capture import JSONPacketSource, SimulatorPacketSource
from .dashboard import DashboardData
from .metrics import TrafficMetrics
from .packets import Packet
from .topology import NetworkTopology


def _load_packets(source: Iterable[Packet]) -> List[Packet]:
    return list(source)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Network traffic analyzer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", type=Path, help="Path to newline-delimited JSON packet capture")
    group.add_argument(
        "--simulate",
        type=Path,
        help="Path to the compiled simulator binary (see c/ directory)",
    )
    parser.add_argument("--count", type=int, default=256, help="Number of packets to request from the simulator")
    parser.add_argument("--seed", type=int, default=None, help="Seed for the simulator")
    args = parser.parse_args(argv)

    if args.input:
        packets = _load_packets(JSONPacketSource(args.input))
    else:
        packets = _load_packets(SimulatorPacketSource(args.simulate, count=args.count, seed=args.seed))

    topology = NetworkTopology()
    metrics = TrafficMetrics()
    for packet in packets:
        topology.ingest_packet(packet)
        metrics.record_packet(packet)

    dashboard = DashboardData(metrics=metrics, topology=topology)
    print(dashboard.to_markdown())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
