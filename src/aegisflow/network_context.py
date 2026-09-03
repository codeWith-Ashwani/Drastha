"""Operator-owned network boundaries; no assumptions based on RFC1918 alone."""
from dataclasses import dataclass, replace
from ipaddress import ip_address, ip_network


@dataclass(frozen=True)
class NetworkScope:
    internal_cidrs: tuple[str, ...] = ()

    def __post_init__(self):
        for cidr in self.internal_cidrs:
            ip_network(cidr, strict=True)

    def direction(self, source, destination):
        if not self.internal_cidrs:
            return "unknown"
        networks = [ip_network(cidr) for cidr in self.internal_cidrs]
        origin = any(ip_address(source) in network for network in networks)
        response = any(ip_address(destination) in network for network in networks)
        return "internal" if origin and response else "outbound" if origin else "inbound" if response else "external"

    def exfiltration_view(self, event):
        direction = self.direction(event.src_ip, event.dst_ip)
        if direction == "outbound":
            return event
        if direction != "inbound":
            return None
        # Preserve Zeek initiator semantics for other detectors; only this view
        # expresses the monitored host's sent/received bytes for exfiltration.
        return replace(event, src_ip=event.dst_ip, dst_ip=event.src_ip,
                       src_port=event.dst_port, dst_port=event.src_port,
                       outbound_bytes=event.inbound_bytes, inbound_bytes=event.outbound_bytes,
                       outbound_packets=event.inbound_packets, inbound_packets=event.outbound_packets)
