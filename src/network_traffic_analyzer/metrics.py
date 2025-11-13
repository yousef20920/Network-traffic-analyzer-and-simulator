"""Utilities for computing latency/throughput metrics from captured packets."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from statistics import mean
from typing import Dict, Iterable, List, Tuple

from .packets import Packet, sliding_window

Link = Tuple[str, str]


@dataclass
class TrafficMetrics:
    """Aggregate latency and throughput measurements by link."""

    latency_samples: Dict[Link, List[float]] = field(default_factory=lambda: defaultdict(list))
    throughput_samples: Dict[Link, List[float]] = field(default_factory=lambda: defaultdict(list))

    def record_packet(self, packet: Packet) -> None:
        link = (packet.src_ip, packet.dst_ip)
        if packet.latency_ms is not None:
            self.latency_samples[link].append(packet.latency_ms)
        if packet.throughput_mbps is not None:
            self.throughput_samples[link].append(packet.throughput_mbps)

    def extend(self, packets: Iterable[Packet]) -> None:
        for packet in packets:
            self.record_packet(packet)

    def average_latency(self) -> Dict[Link, float]:
        return {link: mean(values) for link, values in self.latency_samples.items() if values}

    def average_throughput(self) -> Dict[Link, float]:
        return {link: mean(values) for link, values in self.throughput_samples.items() if values}

    def detect_bottlenecks(
        self,
        latency_threshold: float = 80.0,
        throughput_threshold: float = 100.0,
    ) -> List[dict]:
        """Identify links that exceed latency or fall below throughput thresholds."""

        bottlenecks: List[dict] = []
        avg_latency = self.average_latency()
        avg_throughput = self.average_throughput()
        for link in set(avg_latency) | set(avg_throughput):
            latency = avg_latency.get(link)
            throughput = avg_throughput.get(link)
            if (latency is not None and latency > latency_threshold) or (
                throughput is not None and throughput < throughput_threshold
            ):
                bottlenecks.append(
                    {
                        "link": link,
                        "latency_ms": latency,
                        "throughput_mbps": throughput,
                    }
                )
        return bottlenecks

    def rolling_throughput(self, packets: Iterable[Packet], window: float = 1.0) -> Dict[Link, float]:
        """Compute rolling throughput per link within the provided window."""

        totals: Dict[Link, float] = defaultdict(float)
        counts: Dict[Link, int] = defaultdict(int)
        for bucket in sliding_window(packets, window):
            totals.clear()
            counts.clear()
            for packet in bucket:
                if packet.throughput_mbps is None:
                    continue
                link = (packet.src_ip, packet.dst_ip)
                totals[link] += packet.throughput_mbps
                counts[link] += 1
        return {link: totals[link] / counts[link] for link in totals if counts[link]}
