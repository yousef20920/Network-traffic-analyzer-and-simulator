"""Network traffic analyzer and simulator package."""

from .packets import Packet
from .capture import JSONPacketSource, SimulatorPacketSource
from .protocols.bgp import parse_bgp_update, BgpUpdate
from .protocols.ospf import parse_ospf_lsas, OspfRouterLsa
from .topology import NetworkTopology
from .metrics import TrafficMetrics
from .dashboard import DashboardData

__all__ = [
    "Packet",
    "JSONPacketSource",
    "SimulatorPacketSource",
    "parse_bgp_update",
    "BgpUpdate",
    "parse_ospf_lsas",
    "OspfRouterLsa",
    "NetworkTopology",
    "TrafficMetrics",
    "DashboardData",
]
