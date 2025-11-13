# Network Traffic Analyzer & Simulator

This project implements a miniature network traffic analysis toolkit designed to
capture, decode and visualise routing behaviour on TCP/IP networks.  It is
centred around three pillars:

* **Packet analysis** – inspect captured traffic, decode BGP UPDATE messages and
  OSPF Router-LSAs and aggregate the resulting routing information.
* **Network topology mapping** – correlate routing updates to build a topology
  graph and track prefix reachability and optimal paths.
* **Operational insight** – compute latency/throughput statistics and highlight
  potential bottlenecks using a lightweight dashboard.

The repository contains a Python package with the analysis logic as well as a C
based traffic simulator that emits synthetic BGP and OSPF packets which mimic a
small ISP network.

## Project layout

```
├── c/
│   ├── Makefile            # Build rules for the simulator
│   └── packet_generator.c  # Generates synthetic traffic as JSON lines
├── src/network_traffic_analyzer/
│   ├── capture.py          # Helpers for loading packets and invoking simulator
│   ├── cli.py              # Command line interface
│   ├── dashboard.py        # Dashboard summary generation
│   ├── metrics.py          # Latency/throughput aggregation helpers
│   ├── packets.py          # Packet data model
│   ├── protocols/
│   │   ├── bgp.py          # BGP UPDATE parser
│   │   └── ospf.py         # OSPF LS Update parser
│   └── topology.py         # Topology reconstruction and graph logic
└── tests/
    └── ...                 # Unit tests for the analyzers and topology builder
```

## Building the simulator

```
cd c
make
```

This produces a `packet_generator` executable that emits JSON encoded packet
captures to standard output.  The payloads are serialised as hexadecimal strings
that correspond to actual BGP UPDATE and OSPF LS Update packets.

## Running the analyzer

### From a JSON capture

```
python -m network_traffic_analyzer.cli --input path/to/capture.json
```

### Using the simulator

```
python -m network_traffic_analyzer.cli --simulate ./c/packet_generator --count 128 --seed 42
```

The CLI prints a Markdown summary that includes:

* discovered nodes and links
* averaged latency and throughput per link
* detected bottlenecks beyond configurable thresholds

## Development

Install dependencies (for the tests only the Python standard library is used)
and run the test-suite via:

```
pip install -e .
pytest
```
