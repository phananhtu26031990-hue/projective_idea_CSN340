"""
SynFloodRule – Phát hiện SYN Flood Attack
==========================================
SYN Flood là một loại tấn công DDoS khai thác quy trình bắt tay TCP 3 bước:

  Bình thường (TCP 3-way Handshake):
    Client → [SYN] → Server
    Server → [SYN-ACK] → Client
    Client → [ACK] → Server  ✓ Kết nối thành công

  Tấn công SYN Flood:
    Attacker → [SYN] (IP giả) → Server
    Server → [SYN-ACK] → IP giả (không tồn tại)
    Server chờ ACK... chờ mãi → Half-open connection
    Làm đầy bảng kết nối → Server không nhận thêm kết nối mới → DoS

Logic phát hiện:
  - Đếm số gói SYN từ mỗi IP nguồn trong 1 traffic window
  - Nếu SYN_count[ip] >= threshold → đây là bất thường
  - Tạo Alert với severity = CRITICAL

Ngưỡng mặc định: 100 gói SYN / window
"""

import sys
import os
from datetime import datetime
from typing import List, Dict
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
from models.traffic import Traffic
from models.alert import Alert
from detection.ruleInterface import Rule


class SynFloodRule(Rule):
    """
    Rule phát hiện SYN Flood dựa trên số lượng gói SYN bất thường từ 1 IP.
    """

    def __init__(self, threshold: float = 100.0):
        """
        Args:
            threshold (float): Số lượng gói SYN tối đa cho phép từ 1 IP trong 1 window.
                               Vượt ngưỡng → alert.
        """
        self._threshold = threshold

    @property
    def ruleName(self) -> str:
        return "SynFloodDetection"

    def analyze(self, traffic: Traffic) -> List[Alert]:
        """
        Phân tích traffic window để phát hiện SYN Flood.

        Thuật toán:
          1. Lọc tất cả gói TCP có flag SYN (và không có ACK → là SYN mới, không phải SYN-ACK)
          2. Đếm số gói SYN theo IP nguồn
          3. IP nào vượt ngưỡng → tạo Alert

        Args:
            traffic (Traffic): Cửa sổ traffic cần phân tích

        Returns:
            List[Alert]: Danh sách Alert phát hiện được
        """
        # Đếm gói SYN thuần (SYN=1, ACK=0) từ mỗi IP nguồn
        # SYN-ACK (SYN=1, ACK=1) là phản hồi bình thường của server, không đếm
        syn_counts: Dict[str, int] = defaultdict(int)

        for packet in traffic.packets:
            if (packet.isTCP()
                    and "SYN" in packet.tcpFlags
                    and "ACK" not in packet.tcpFlags):       # Chỉ tính SYN thuần
                syn_counts[packet.srcIp] += 1

        alerts: List[Alert] = []

        for src_ip, count in syn_counts.items():
            if count >= self._threshold:
                # Tìm IP đích bị tấn công (IP xuất hiện nhiều nhất trong các gói SYN từ src_ip)
                dst_ip_counts: Dict[str, int] = defaultdict(int)
                for packet in traffic.packets:
                    if (packet.isTCP()
                            and packet.srcIp == src_ip
                            and "SYN" in packet.tcpFlags
                            and "ACK" not in packet.tcpFlags):
                        dst_ip_counts[packet.dstIp] += 1

                target_ip = max(dst_ip_counts, key=dst_ip_counts.get) if dst_ip_counts else "unknown"

                # Tính confidence: càng nhiều SYN hơn ngưỡng → confidence càng cao
                confidence = min(0.99, 0.70 + (count - self._threshold) / (self._threshold * 2))

                alerts.append(Alert(
                    id=0,  # ID sẽ được gán bởi RuleEngine
                    ruleName=self.ruleName,
                    attackType="SYN Flood",
                    sourceIp=src_ip,
                    destinationIp=target_ip,
                    severity="critical",
                    confidence=round(confidence, 4),
                    timestamp=traffic.endTime or datetime.now(),
                    description=(
                        f"Phát hiện SYN Flood từ {src_ip}: {count} gói SYN "
                        f"(ngưỡng: {self._threshold}) trong cửa sổ "
                        f"{traffic.startTime} → {traffic.endTime}. "
                        f"Mục tiêu: {target_ip}. "
                        f"Server có thể bị làm đầy bảng half-open connection."
                    )
                ))

        return alerts
