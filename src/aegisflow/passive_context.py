"""Bounded causal DNS context. Association is evidence, never a trust decision."""
from collections import deque
import json

from aegisflow.models import Evidence


class PassiveDNSContext:
    def __init__(self, maximum_records=10_000, window_seconds=60):
        self.history = deque(maxlen=maximum_records)
        self.window_seconds = window_seconds

    def observe(self, event):
        self.history.append(event)

    def evidence_for(self, event):
        cutoff = event.timestamp - self.window_seconds
        while self.history and self.history[0].timestamp < cutoff:
            self.history.popleft()
        matches = []
        for dns in reversed(self.history):
            if not cutoff <= dns.timestamp <= event.timestamp or dns.src_ip != event.src_ip:
                continue
            if (dns.flow_id == event.flow_id and dns.dst_ip == event.dst_ip) or event.dst_ip in dns.answers:
                matches.append({"query": dns.query, "dns_flow_id": dns.flow_id, "observed_at": dns.timestamp,
                                "join": "uid-and-endpoints" if dns.flow_id == event.flow_id and dns.dst_ip == event.dst_ip else "source-and-answer-IP"})
            if len(matches) == 20:
                break
        return (Evidence("observed_dns_context", json.dumps(matches, sort_keys=True),
                         "prior 60 seconds; at most 20 observations", "Passive temporal association only; not DNS reputation, ownership, or proof this flow used the name."),) if matches else ()
