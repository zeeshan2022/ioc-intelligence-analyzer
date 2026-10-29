"""Connector package (threat-intelligence integrations).

Release 1 ships VirusTotal, AbuseIPDB and GreyNoise. AlienVault OTX, URLHaus,
Shodan, Whois and DNS are stubbed behind the same abstract interface so future
releases can plug them in without refactoring (Open/Closed principle).
"""

from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.virustotal import VirusTotalConnector
from app.connectors.abuseipdb import AbuseIPDBConnector
from app.connectors.greynoise import GreyNoiseConnector

__all__ = [
    "AbuseIPDBConnector",
    "BaseConnector",
    "ConnectorError",
    "GreyNoiseConnector",
    "VirusTotalConnector",
]
