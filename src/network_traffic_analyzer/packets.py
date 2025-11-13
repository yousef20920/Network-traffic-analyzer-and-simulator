"""Data models for representing captured packets and decoded payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, Optional


@dataclass(slots=True)
class Packet:
    """Simplified representation of a captured packet.

    The analyzer focuses on metadata that is typically useful for traffic
    engineering: timestamps, addresses, payload length and auxiliary metrics.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    transport_protocol: str
    payload_protocol: Optional[str]
    length: int
    payload: bytes
    latency_ms: Optional[float] = None
    throughput_mbps: Optional[float] = None
    metadata: Dict[str, object] = field(default_factory=dict)

    def copy_with(self, **updates: object) -> "Packet":
        """Return a copy of the packet with a subset of fields updated."""

        data = {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "transport_protocol": self.transport_protocol,
            "payload_protocol": self.payload_protocol,
            "length": self.length,
            "payload": self.payload,
            "latency_ms": self.latency_ms,
            "throughput_mbps": self.throughput_mbps,
            "metadata": dict(self.metadata),
        }
        data.update(updates)
        return Packet(**data)


def sliding_window(packets: Iterable[Packet], window: float) -> Iterator[list[Packet]]:
    """Yield packets grouped in sliding time windows.

    The function keeps a rolling buffer of packets whose timestamp falls within
    ``window`` seconds of the most recent packet. It is primarily used for
    throughput calculations.
    """

    bucket: list[Packet] = []
    for packet in packets:
        bucket.append(packet)
        # Discard entries outside of the window interval.
        threshold = packet.timestamp - window
        bucket = [item for item in bucket if item.timestamp >= threshold]
        yield bucket
