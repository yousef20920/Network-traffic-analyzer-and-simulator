"""Utilities for ingesting packet captures from various sources."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from .packets import Packet


class PacketSource(Iterable[Packet]):
    """Abstract iterable that yields :class:`~network_traffic_analyzer.packets.Packet`."""

    def __iter__(self) -> Iterator[Packet]:  # pragma: no cover - interface definition
        raise NotImplementedError


class JSONPacketSource(PacketSource):
    """Load packets from a JSON file.

    Each line in the file must contain a JSON object with the following keys:

    ``timestamp`` (float)
        Packet capture timestamp.
    ``src_ip`` / ``dst_ip`` (str)
        Source and destination IPv4 addresses.
    ``transport_protocol`` (str)
        The transport protocol name (e.g. ``"TCP"``).
    ``payload_protocol`` (str)
        Protocol carried inside the transport payload (``"BGP"`` or ``"OSPF"``).
    ``length`` (int)
        Payload length in bytes.
    ``payload_hex`` (str)
        Hex encoded payload for protocol decoding.
    Optional keys ``latency_ms`` and ``throughput_mbps`` provide metrics used by
    the dashboard.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def __iter__(self) -> Iterator[Packet]:
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                yield _record_to_packet(record)


class SimulatorPacketSource(PacketSource):
    """Invoke the bundled C simulator to produce synthetic traffic."""

    def __init__(
        self,
        executable: Path | str,
        count: int = 256,
        seed: Optional[int] = None,
    ) -> None:
        self.executable = Path(executable)
        self.count = count
        self.seed = seed

    def __iter__(self) -> Iterator[Packet]:
        if not self.executable.exists():
            raise FileNotFoundError(
                f"Simulator executable '{self.executable}' does not exist. Did you run 'make' in the c/ directory?"
            )

        command: List[str] = [str(self.executable), str(self.count)]
        if self.seed is not None:
            command.append(str(self.seed))

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        assert process.stdout is not None
        for line in process.stdout:
            if not line.strip():
                continue
            record = json.loads(line)
            yield _record_to_packet(record)
        process.stdout.close()
        stderr_output = process.stderr.read()
        return_code = process.wait()
        if return_code != 0:
            raise RuntimeError(
                f"Simulator exited with {return_code}: {stderr_output.strip()}"
            )


def _record_to_packet(record: dict) -> Packet:
    payload_hex = record.get("payload_hex", "")
    payload = bytes.fromhex(payload_hex)
    return Packet(
        timestamp=float(record["timestamp"]),
        src_ip=record["src_ip"],
        dst_ip=record["dst_ip"],
        transport_protocol=record.get("transport_protocol", record.get("protocol", "TCP")),
        payload_protocol=record.get("payload_protocol"),
        length=int(record.get("length", len(payload))),
        payload=payload,
        latency_ms=float(record["latency_ms"]) if "latency_ms" in record else None,
        throughput_mbps=float(record["throughput_mbps"]) if "throughput_mbps" in record else None,
        metadata={key: value for key, value in record.items() if key.startswith("meta_")},
    )
