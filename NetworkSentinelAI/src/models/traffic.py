from datetime import datetime
from typing import List, Optional, Dict
from .packet import Packet

class Traffic:
    """
    Aggregates collections of Packet objects to represent network flows/traffic over time windows.
    Provides analytics and statistical summary metrics.
    """
    def __init__(self):
        self.packets: List[Packet] = []
        self.totalPackets: int = 0
        self.totalByte: int = 0
        self.sourceIps: List[str] = []
        self.destinationIps: List[str] = []
        self.startTime: Optional[datetime] = None   # Thời gian bắt đầu của traffic window, dùng optional để có thể ban đầu là None 
        self.endTime: Optional[datetime] = None     # Thời gian kết thúc của traffic window, dùng optional để có thể ban đầu là None

    def addPacket(self, packet: Packet) -> None:
        """
        Adds a packet to the current window, updating statistics dynamically.
        """
        self.packets.append(packet)
        self.totalPackets += 1
        self.totalByte += packet.length
        
        # Maintain uniqueness while preserving order of discovery
        if packet.srcIp not in self.sourceIps:
            self.sourceIps.append(packet.srcIp)
        if packet.dstIp not in self.destinationIps:
            self.destinationIps.append(packet.dstIp)
            
        # Update window boundary timestamps
        if self.startTime is None or packet.timestamp < self.startTime:
            self.startTime = packet.timestamp
        if self.endTime is None or packet.timestamp > self.endTime:
            self.endTime = packet.timestamp

    def getDuration(self) -> float:
        """
        Calculates the duration of the traffic window in seconds.
        """
        if not self.startTime or not self.endTime:
            return 0.0
        return (self.endTime - self.startTime).total_seconds()

    def calculateRate(self) -> float:
        """
        Calculates the average packet transmission rate in Packets Per Second (pps).
        """
        duration = self.getDuration()
        if not duration or self.totalPackets <= 1:
            return 0.0
        return self.totalPackets / duration
    def calculateByteRate(self) -> float:
        """
        Calculates the average byte transmission rate in Bytes Per Second (Bps).
        """
        duration = self.getDuration()
        if not duration or self.totalByte <= 1:
            return 0.0
        return self.totalByte / duration

    def getStatistics(self) -> dict:
        """
        Generates an aggregated metric dashboard dictionary of the traffic window.
        """
        duration = self.getDuration()
        packet_rate = self.calculateRate()
        byte_rate = self.calculateByteRate()
        
        # Count protocols
        protocolCounts: Dict[str, int] = {}   # [ key , value ] là [ protocol , count ]
        for p in self.packets:   # lấy từng phần tử trong list packets
            proto = p.protocol
            protocolCounts[proto] = protocolCounts.get(proto, 0) + 1  # Lấy value tương ứng với một key. Nếu key chưa tồn tại thì trả về giá trị mặc định (default)
                                                                        # Ví dụ: 
                                                                        # protocolCounts = {"TCP": 1} 
                                                                        # p.protocol = "TCP"
                                                                        # protocolCounts.get("TCP", 0) trả về 1
                                                                        # protocolCounts["TCP"] = 1 + 1 = 2
        return {
            "totalPackets": self.totalPackets,
            "totalByte": self.totalByte,
            "startTime": self.startTime.isoformat() if self.startTime else None,
            "endTime": self.endTime.isoformat() if self.endTime else None,
            "durationSeconds": duration,
            "packetRatePps": packet_rate,
            "byteRateBps": byte_rate,
            "sourceIps": self.sourceIps,
            "destinationIps": self.destinationIps,
            "protocolCounts": protocolCounts,
            "uniqueSourceIpsCount": len(self.sourceIps),
            "uniqueDestinationIpsCount": len(self.destinationIps)
        }
