"""
PacketParser – Layer 2: Parsing Layer
=======================================
Phân tích và xây dựng Packet object từ dữ liệu thô dạng dictionary.

Trường hợp sử dụng:
  1. Đọc lại packet từ log JSON/CSV đã lưu
  2. Nhận packet từ API hoặc message queue (Kafka, Redis...)
  3. Tạo mock packet cho unit test
  4. Nhận dữ liệu từ các nguồn capture khác (không dùng PyShark)

So sánh với PySharkAdapter:
  - PySharkAdapter: chuyển từ PyShark object (live capture)
  - PacketParser: chuyển từ Python dict (data đã serialize)
"""

import sys
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.packet import Packet


class PacketParser:
    """
    Xây dựng và validate Packet object từ dữ liệu dictionary.

    Hỗ trợ cả dữ liệu đầy đủ lẫn thiếu field (dùng giá trị mặc định).
    """

    # Bộ đếm ID để đảm bảo mỗi packet có ID duy nhất khi không cung cấp
    _packet_counter: int = 0

    @classmethod
    def fromDict(cls, data: Dict[str, Any]) -> Packet:
        """
        Tạo Packet object từ dictionary.

        Dictionary keys hợp lệ (đều optional với giá trị mặc định):
          - id (int): ID gói tin
          - timestamp (str/datetime): Thời gian bắt gói tin (ISO format string hoặc datetime)
          - srcIp (str): IP nguồn
          - dstIp (str): IP đích
          - srcPort (int): Port nguồn
          - dstPort (int): Port đích
          - protocol (str): Giao thức (TCP/UDP/ICMP)
          - tcpFlags (list): Danh sách cờ TCP
          - length (int): Độ dài gói tin (bytes)
          - srcMac (str): MAC nguồn
          - dstMac (str): MAC đích
          - ttl (int): Time To Live
          - payload (str/bytes): Dữ liệu payload (hex string hoặc bytes)
          - interface (str): Tên card mạng

        Args:
            data (dict): Dictionary chứa thông tin packet

        Returns:
            Packet: Packet object đã được tạo và validate
        """
        cls._packet_counter += 1

        # ── Xử lý timestamp ─────────────────────────────────────────────────
        timestamp = data.get("timestamp", None)
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                timestamp = datetime.now()
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now()

        # ── Xử lý payload ───────────────────────────────────────────────────
        payload = data.get("payload", b"")
        if isinstance(payload, str):
            try:
                payload = bytes.fromhex(payload)    # Hex string → bytes
            except ValueError:
                payload = payload.encode()          # Plain string → bytes
        elif not isinstance(payload, bytes):
            payload = b""

        # ── Xử lý TCP flags ──────────────────────────────────────────────────
        tcp_flags = data.get("tcpFlags", [])
        if not isinstance(tcp_flags, list):
            tcp_flags = []

        return Packet(
            id=data.get("id", cls._packet_counter),
            timestamp=timestamp,
            srcIp=str(data.get("srcIp", "0.0.0.0")),
            dstIp=str(data.get("dstIp", "0.0.0.0")),
            srcPort=int(data.get("srcPort", 0)),
            dstPort=int(data.get("dstPort", 0)),
            protocol=str(data.get("protocol", "UNKNOWN")),
            tcpFlags=tcp_flags,
            length=int(data.get("length", 0)),
            srcMac=str(data.get("srcMac", "00:00:00:00:00:00")),
            dstMac=str(data.get("dstMac", "00:00:00:00:00:00")),
            ttl=int(data.get("ttl", 0)),
            payload=payload,
            interface=str(data.get("interface", "unknown")),
        )

    @classmethod
    def fromArgs(
        cls,
        srcIp: str,
        dstIp: str,
        protocol: str,
        length: int,
        srcPort: int = 0,
        dstPort: int = 0,
        tcpFlags: Optional[List[str]] = None,
        ttl: int = 64,
        payload: bytes = b"",
        interface: str = "eth0",
        timestamp: Optional[datetime] = None,
        srcMac: str = "00:00:00:00:00:00",
        dstMac: str = "00:00:00:00:00:00",
    ) -> Packet:
        """
        Tạo Packet object trực tiếp từ các tham số (dùng trong test hoặc simulation).

        Args:
            srcIp: IP nguồn
            dstIp: IP đích
            protocol: Giao thức ("TCP", "UDP", "ICMP")
            length: Kích thước gói tin (bytes)
            srcPort: Port nguồn (0 với ICMP)
            dstPort: Port đích (0 với ICMP)
            tcpFlags: Danh sách cờ TCP (None → [])
            ttl: Time To Live
            payload: Dữ liệu payload
            interface: Tên card mạng
            timestamp: Thời gian. Mặc định: datetime.now()
            srcMac: MAC nguồn
            dstMac: MAC đích

        Returns:
            Packet: Packet object mới
        """
        cls._packet_counter += 1
        return Packet(
            id=cls._packet_counter,
            timestamp=timestamp or datetime.now(),
            srcIp=srcIp,
            dstIp=dstIp,
            srcPort=srcPort,
            dstPort=dstPort,
            protocol=protocol,
            tcpFlags=tcpFlags or [],
            length=length,
            srcMac=srcMac,
            dstMac=dstMac,
            ttl=ttl,
            payload=payload,
            interface=interface,
        )
