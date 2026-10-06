"""
PySharkAdapter – Adapter Pattern
=================================
Mục đích:
  Chuyển đổi raw packet object từ thư viện PyShark thành Packet model
  nội bộ của hệ thống. Tách biệt hoàn toàn thư viện bên ngoài khỏi
  logic core → dễ thay thế hoặc mock khi test.

Thiết kế Adapter:
  PyShark Packet (bên ngoài)
      ↓  PySharkAdapter.convert()
  Packet (models nội bộ)

Lý do dùng Adapter Pattern:
  - Nếu sau này đổi từ PyShark sang scapy/dpkt, chỉ cần sửa file này
  - Các layer khác (parsing, detection...) không cần biết PyShark tồn tại
"""

from datetime import datetime
from typing import List
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.packet import Packet


class PySharkAdapter:
    """
    Adapter chuyển đổi pyshark packet object → Packet model nội bộ.

    PyShark đọc thông tin từ các layer khác nhau trong packet (eth, ip, tcp/udp/icmp).
    Adapter này trích xuất và chuẩn hóa chúng thành Packet với các field nhất quán.
    """

    # Bộ đếm ID tự tăng (shared across all instances)
    _packet_counter: int = 0

    @classmethod
    def convert(cls, raw_packet, interface: str = "unknown") -> Packet:
        """
        Chuyển đổi một raw PyShark packet thành Packet object.

        Args:
            raw_packet: PyShark packet object (từ pyshark.LiveCapture hoặc FileCapture)
            interface (str): Tên card mạng đang bắt gói tin

        Returns:
            Packet: Packet object đã được chuẩn hóa
        """
        cls._packet_counter += 1
        packet_id = cls._packet_counter

        # ── Timestamp ────────────────────────────────────────────────────────
        # PyShark lưu sniff_time là datetime object, sniff_timestamp là epoch float
        try:
            timestamp = raw_packet.sniff_time
        except AttributeError:
            timestamp = datetime.now()

        # ── Layer 3: IP ───────────────────────────────────────────────────────
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        ttl = 0
        protocol_str = "UNKNOWN"

        if hasattr(raw_packet, 'ip'):
            src_ip = str(raw_packet.ip.src)
            dst_ip = str(raw_packet.ip.dst)
            ttl = int(raw_packet.ip.ttl)
            protocol_str = str(raw_packet.ip.proto)  # Số protocol (6=TCP, 17=UDP, 1=ICMP)

        # ── Layer 2: Ethernet ─────────────────────────────────────────────────
        src_mac = "00:00:00:00:00:00"
        dst_mac = "00:00:00:00:00:00"

        if hasattr(raw_packet, 'eth'):
            src_mac = str(raw_packet.eth.src)
            dst_mac = str(raw_packet.eth.dst)

        # ── Layer 4: TCP / UDP / ICMP ─────────────────────────────────────────
        src_port = 0
        dst_port = 0
        tcp_flags: List[str] = []
        protocol_name = "UNKNOWN"
        payload = b""

        if hasattr(raw_packet, 'tcp'):
            protocol_name = "TCP"
            src_port = int(raw_packet.tcp.srcport)
            dst_port = int(raw_packet.tcp.dstport)
            tcp_flags = cls._extractTcpFlags(raw_packet.tcp)
            # Lấy payload của TCP nếu có
            if hasattr(raw_packet.tcp, 'payload'):
                try:
                    payload = bytes.fromhex(str(raw_packet.tcp.payload).replace(':', ''))
                except (ValueError, AttributeError):
                    payload = b""

        elif hasattr(raw_packet, 'udp'):
            protocol_name = "UDP"
            src_port = int(raw_packet.udp.srcport)
            dst_port = int(raw_packet.udp.dstport)
            if hasattr(raw_packet.udp, 'payload'):
                try:
                    payload = bytes.fromhex(str(raw_packet.udp.payload).replace(':', ''))
                except (ValueError, AttributeError):
                    payload = b""

        elif hasattr(raw_packet, 'icmp'):
            protocol_name = "ICMP"
            # ICMP không có port, để 0
            if hasattr(raw_packet.icmp, 'data'):
                try:
                    payload = bytes.fromhex(str(raw_packet.icmp.data).replace(':', ''))
                except (ValueError, AttributeError):
                    payload = b""

        else:
            # Fallback: dựa vào protocol number từ IP header
            protocol_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
            protocol_name = protocol_map.get(protocol_str, protocol_str)

        # ── Packet length ──────────────────────────────────────────────────────
        try:
            length = int(raw_packet.length)
        except AttributeError:
            length = 0

        return Packet(
            id=packet_id,
            timestamp=timestamp,
            srcIp=src_ip,
            dstIp=dst_ip,
            srcPort=src_port,
            dstPort=dst_port,
            protocol=protocol_name,
            tcpFlags=tcp_flags,
            length=length,
            srcMac=src_mac,
            dstMac=dst_mac,
            ttl=ttl,
            payload=payload,
            interface=interface,
        )

    @staticmethod
    def _extractTcpFlags(tcp_layer) -> List[str]:
        """
        Trích xuất danh sách cờ TCP đang được bật từ TCP layer.

        Cờ TCP (RFC 793):
          - SYN: Synchronize (khởi tạo kết nối)
          - ACK: Acknowledge (xác nhận)
          - FIN: Finish (kết thúc kết nối)
          - RST: Reset (đặt lại kết nối)
          - PSH: Push (đẩy data lên ứng dụng ngay)
          - URG: Urgent (dữ liệu khẩn cấp)

        Args:
            tcp_layer: PyShark TCP layer object

        Returns:
            List[str]: Danh sách tên cờ đang bật, ví dụ ["SYN", "ACK"]
        """
        flags = []
        flag_map = {
            "flags_syn": "SYN",
            "flags_ack": "ACK",
            "flags_fin": "FIN",
            "flags_rst": "RST",
            "flags_push": "PSH",
            "flags_urg": "URG",
        }
        for attr, name in flag_map.items():    #cách viết vòng lập cặp key, value của map
            try:
                if str(getattr(tcp_layer, attr)) in ("1", "True"): # biểu diễn cho cờ tcp đang bật (1 hoặc True)
                    flags.append(name)
            except AttributeError:
                continue
        return flags
