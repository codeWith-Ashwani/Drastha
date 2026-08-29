"""Threat-specific detector modules."""

from aegisflow.detectors.recon import ReconConfig, ReconDetector
from aegisflow.detectors.ddos import DDoSConfig, DDoSDetector
from aegisflow.detectors.dns import DNSConfig, DNSDetector
from aegisflow.detectors.c2 import C2BeaconDetector, C2Config
from aegisflow.detectors.exfiltration import ExfiltrationConfig, ExfiltrationDetector

__all__ = [
    "C2BeaconDetector", "C2Config", "DDoSConfig", "DDoSDetector", "DNSConfig", "DNSDetector",
    "ExfiltrationConfig", "ExfiltrationDetector", "ReconConfig", "ReconDetector"
]
