"""Produce dashboard-friendly summaries of the analyzed traffic."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .metrics import TrafficMetrics
from .topology import NetworkTopology


@dataclass
class DashboardData:
    metrics: TrafficMetrics
    topology: NetworkTopology

    def summary(self) -> Dict[str, object]:
        avg_latency = {
            f"{src}->{dst}": value for (src, dst), value in self.metrics.average_latency().items()
        }
        avg_throughput = {
            f"{src}->{dst}": value for (src, dst), value in self.metrics.average_throughput().items()
        }
        bottlenecks = [
            {
                "link": f"{src}->{dst}",
                "latency_ms": entry.get("latency_ms"),
                "throughput_mbps": entry.get("throughput_mbps"),
            }
            for entry in self.metrics.detect_bottlenecks()
            for src, dst in [entry["link"]]
        ]
        return {
            "nodes": sorted(self.topology.nodes),
            "links": {
                f"{src}->{dst}": {
                    "metric": metadata.metric,
                    "protocols": sorted(metadata.protocols),
                }
                for (src, dst), metadata in self.topology.links.items()
            },
            "average_latency_ms": avg_latency,
            "average_throughput_mbps": avg_throughput,
            "bottlenecks": bottlenecks,
        }

    def to_markdown(self) -> str:
        summary = self.summary()
        lines: List[str] = ["# Network Traffic Dashboard", "", "## Nodes", ", ".join(summary["nodes"]) or "None"]
        lines.append("\n## Links")
        for link, metadata in summary["links"].items():
            lines.append(
                f"- **{link}**: metric={metadata['metric']}, protocols={', '.join(metadata['protocols'])}"
            )
        lines.append("\n## Average Latency (ms)")
        for link, value in summary["average_latency_ms"].items():
            lines.append(f"- {link}: {value:.2f}")
        lines.append("\n## Average Throughput (Mbps)")
        for link, value in summary["average_throughput_mbps"].items():
            lines.append(f"- {link}: {value:.2f}")
        lines.append("\n## Potential Bottlenecks")
        if not summary["bottlenecks"]:
            lines.append("- None detected")
        else:
            for entry in summary["bottlenecks"]:
                latency = entry.get("latency_ms")
                throughput = entry.get("throughput_mbps")
                lines.append(
                    f"- {entry['link']}: latency={latency:.2f} ms, throughput={throughput:.2f} Mbps"
                    if latency is not None and throughput is not None
                    else f"- {entry['link']}: latency={latency}, throughput={throughput}"
                )
        return "\n".join(lines)
