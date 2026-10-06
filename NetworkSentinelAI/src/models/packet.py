from datetime import datetime
from typing import List, Dict, Any

class Packet:
    """
    Represents a single network packet with its key metadata and headers.
    """

    def __init__(
        self,
        id: int,
        timestamp: datetime,
        srcIp: str,
        dstIp: str,
        srcPort: int,
        dstPort: int,
        protocol: str,
        tcpFlags: List[str],
        length: int,
        srcMac: str,
        dstMac: str,
        ttl: int,
        payload: bytes,
        interface: str,
    ):
        self.id = id
        self.timestamp = timestamp
        self.srcIp = srcIp
        self.dstIp = dstIp
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.protocol = protocol.upper()
        self.tcpFlags = tcpFlags
        self.length = length
        self.srcMac = srcMac
        self.dstMac = dstMac
        self.ttl = ttl
        self.payload = payload
        self.interface = interface

    def getSummary(self) -> str:
        """
        Returns a concise, human-readable summary of the packet transmission.
        """
        summary = f"Packet #{self.id} | {self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} | "  # Năm-Tháng-Ngày Giờ:Phút:Giây.Microsecond [:-3] bỏ 3 số cuối microsecond
        if self.protocol in ("TCP", "UDP"):
            summary += f"{self.protocol} {self.srcIp}:{self.srcPort} -> {self.dstIp}:{self.dstPort}"  # TCP, UDP use source port and destination port in layer 4 (Transport Layer)
        else:
            summary += f"{self.protocol} {self.srcIp} -> {self.dstIp}"  # ICMP use source ip and destination ip in layer 3 (Network Layer)
        summary += f" | Length: {self.length} bytes"

        if (
            self.protocol == "TCP" and self.tcpFlags
        ):  # TCP use flags to indicate the state of the connection
            summary += f" | Flags: [{', '.join(self.tcpFlags)}]"
        return summary

    def isTCP(self) -> bool:
        return self.protocol == "TCP"

    def isUDP(self) -> bool:
        return self.protocol == "UDP"

    def isICMP(self) -> bool:
        return self.protocol == "ICMP"

    def toDictionary(self) -> dict:
        """
        Serializes the Packet object to a clean Python dictionary.
        Safely serializes datetime values and raw byte payload formats.
        """
        return {
            "id": self.id,
            "timestamp": (
                self.timestamp.isoformat()
                if isinstance(self.timestamp, datetime)
                else self.timestamp
            ),
            "srcIp": self.srcIp,
            "dstIp": self.dstIp,
            "srcPort": self.srcPort,
            "dstPort": self.dstPort,
            "protocol": self.protocol,
            "tcpFlags": self.tcpFlags,
            "length": self.length,
            "srcMac": self.srcMac,
            "dstMac": self.dstMac,
            "ttl": self.ttl,
            "payload": (
                self.payload.hex()
                if isinstance(self.payload, bytes)
                else (self.payload or "")
            ),
            "interface": self.interface,
        }
