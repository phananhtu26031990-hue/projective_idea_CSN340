"""
AckFloodRule – Phát hiện ACK Flood Attack
==========================================
ACK Flood là một loại tấn công DDoS gửi số lượng lớn gói ACK giả mạo:

  Bình thường: ACK được gửi để xác nhận dữ liệu đã nhận (trong kết nối TCP)

  Tấn công ACK Flood:
    Attacker → [ACK] (rất nhiều, IP giả) → Server
    Server nhận ACK không thuộc kết nối nào → phải xử lý (tra bảng, gửi RST)
    Làm tốn CPU/memory của server → DoS

  Khác với SYN Flood: ACK Flood nhắm vào giai đoạn TRONG kết nối, không chỉ khởi tạo

Logic phát hiện:
  - Đếm số gói ACK từ mỗi IP nguồn trong window
  - Đặc biệt nguy hiểm khi: chỉ có ACK, không có SYN trước đó (không thuộc session nào)
  - Ngưỡng mặc định: 150 gói ACK / window (cao hơn SYN vì ACK bình thường cũng nhiều)
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


class AckFloodRule(Rule):
    """
    Rule phát hiện ACK Flood dựa trên số lượng gói ACK bất thường từ 1 IP.
    """

    def __init__(self, threshold: float = 150.0):
        """
        Args:
            threshold (float): Số lượng gói ACK tối đa từ 1 IP trong 1 window.
        """
        self._threshold = threshold

    @property
    def ruleName(self) -> str:
        return "AckFloodDetection"

    def analyze(self, traffic: Traffic) -> List[Alert]:
        """
        Phân tích traffic để phát hiện ACK Flood.

        Thuật toán nâng cao:
          1. Đếm tổng ACK từ mỗi IP nguồn
          2. Đếm số SYN từ IP đó (để tính tỉ lệ ACK/SYN)
          3. ACK nhiều mà không có SYN tương ứng → rất đáng ngờ
          4. Nếu vượt ngưỡng → tạo Alert

        Args:
            traffic (Traffic): Cửa sổ traffic cần phân tích

        Returns:
            List[Alert]: Danh sách Alert phát hiện được
        """
        ack_counts: Dict[str, int] = defaultdict(int)
        syn_counts: Dict[str, int] = defaultdict(int)

        for packet in traffic.packets:
            if packet.isTCP():
                if "ACK" in packet.tcpFlags:
                    ack_counts[packet.srcIp] += 1
                if "SYN" in packet.tcpFlags and "ACK" not in packet.tcpFlags:
                    syn_counts[packet.srcIp] += 1

        alerts: List[Alert] = []

        for src_ip, ack_count in ack_counts.items():
            if ack_count >= self._threshold:
                syn_count = syn_counts.get(src_ip, 0)

                # Tính tỉ lệ ACK/SYN: bình thường ≈ 1:1
                # Nếu ACK >> SYN (ví dụ >5:1) → không phải traffic bình thường
                ack_syn_ratio = ack_count / max(syn_count, 1)

                # Confidence càng cao nếu: nhiều ACK và ít SYN
                base_confidence = min(0.95, 0.65 + (ack_count - self._threshold) / (self._threshold * 3))
                ratio_bonus = min(0.10, (ack_syn_ratio - 1) * 0.02) if ack_syn_ratio > 3 else 0
                confidence = min(0.99, base_confidence + ratio_bonus)

                # Tìm IP đích bị tấn công nhiều nhất
                dst_ip_counts: Dict[str, int] = defaultdict(int)
                for packet in traffic.packets:
                    if (packet.isTCP()
                            and packet.srcIp == src_ip
                            and "ACK" in packet.tcpFlags):
                        dst_ip_counts[packet.dstIp] += 1

                target_ip = max(dst_ip_counts, key=dst_ip_counts.get) if dst_ip_counts else "unknown"

                alerts.append(Alert(
                    id=0,
                    ruleName=self.ruleName,
                    attackType="ACK Flood",
                    sourceIp=src_ip,
                    destinationIp=target_ip,
                    severity="high",
                    confidence=round(confidence, 4),
                    timestamp=traffic.endTime or datetime.now(),
                    description=(
                        f"Phát hiện ACK Flood từ {src_ip}: {ack_count} gói ACK "
                        f"(ngưỡng: {self._threshold}), tỉ lệ ACK/SYN: {ack_syn_ratio:.1f}:1. "
                        f"Cửa sổ: {traffic.startTime} → {traffic.endTime}. "
                        f"Mục tiêu: {target_ip}. Server bị buộc xử lý ACK giả mạo."
                    )
                ))

        return alerts
