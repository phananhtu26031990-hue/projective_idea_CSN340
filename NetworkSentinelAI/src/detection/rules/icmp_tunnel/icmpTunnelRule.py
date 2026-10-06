"""
ICMPTunnelRule – Phát hiện ICMP Tunneling
==========================================
ICMP Tunneling là kỹ thuật ẩn dữ liệu trong gói ICMP để vượt qua firewall:

  ICMP bình thường (ping):
    → Echo Request (type=8): payload ≈ 32-64 bytes (thường là chuỗi "abcdef...")
    ← Echo Reply (type=0): payload tương tự, nhỏ

  ICMP Tunneling:
    → Nhúng dữ liệu thật (DNS query, HTTP, shell command...) vào payload ICMP
    → Payload lớn bất thường (có thể > 1000 bytes)
    → Firewall không chặn ICMP → dữ liệu bí mật đi qua được

Phần mềm ICMP Tunnel phổ biến: ptunnel, icmptunnel, hans

Logic phát hiện (2 tín hiệu):
  1. Số lượng ICMP: > threshold gói / window → tần suất bất thường
  2. Payload size: gói ICMP với payload > 100 bytes → nghi ngờ có dữ liệu ẩn
     (ping bình thường chỉ có 32-56 bytes payload)

Ngưỡng mặc định: 30 gói ICMP / window
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

# Payload ICMP bình thường (ping) thường <= 64 bytes
# Trên 100 bytes là dấu hiệu có thể có tunneling
SUSPICIOUS_ICMP_PAYLOAD_SIZE = 100


class ICMPTunnelRule(Rule):
    """
    Rule phát hiện ICMP Tunneling dựa trên:
    1. Số lượng gói ICMP bất thường cao
    2. Payload size của gói ICMP bất thường lớn
    """

    def __init__(self, threshold: float = 30.0):
        """
        Args:
            threshold (float): Số gói ICMP tối đa từ 1 IP trong 1 window.
        """
        self._threshold = threshold

    @property
    def ruleName(self) -> str:
        return "ICMPTunnelDetection"

    def analyze(self, traffic: Traffic) -> List[Alert]:
        """
        Phân tích traffic để phát hiện ICMP Tunneling.

        Thuật toán kết hợp 2 tín hiệu:
          - Tín hiệu 1 (Volume): Đếm số gói ICMP từ mỗi IP nguồn
          - Tín hiệu 2 (Payload): Đếm số gói ICMP có payload lớn bất thường
          - Kết hợp 2 tín hiệu → confidence cao hơn

        Args:
            traffic (Traffic): Cửa sổ traffic cần phân tích

        Returns:
            List[Alert]: Danh sách Alert phát hiện được
        """
        # Thống kê theo IP nguồn
        icmp_counts: Dict[str, int] = defaultdict(int)
        large_payload_counts: Dict[str, int] = defaultdict(int)
        total_payload_sizes: Dict[str, int] = defaultdict(int)
        dst_ip_map: Dict[str, str] = {}                    # src_ip → dst_ip phổ biến nhất

        for packet in traffic.packets:
            if packet.isICMP():
                src_ip = packet.srcIp
                icmp_counts[src_ip] += 1
                payload_size = len(packet.payload) if packet.payload else 0
                total_payload_sizes[src_ip] += payload_size

                # Đếm gói có payload bất thường lớn
                if payload_size > SUSPICIOUS_ICMP_PAYLOAD_SIZE:
                    large_payload_counts[src_ip] += 1

                # Theo dõi IP đích (giữ IP đích xuất hiện nhiều nhất)
                if src_ip not in dst_ip_map:
                    dst_ip_map[src_ip] = packet.dstIp

        alerts: List[Alert] = []

        for src_ip, icmp_count in icmp_counts.items():
            large_payload_count = large_payload_counts.get(src_ip, 0)
            avg_payload = total_payload_sizes.get(src_ip, 0) / max(icmp_count, 1)

            # Điều kiện phát hiện:
            # 1. Số lượng ICMP vượt ngưỡng, HOẶC
            # 2. Số lượng gói payload lớn đủ cao (> 10 gói với payload > 100 bytes)
            volume_triggered = icmp_count >= self._threshold
            payload_triggered = large_payload_count >= max(10, self._threshold * 0.3)

            if not (volume_triggered or payload_triggered):
                continue

            # Tính confidence dựa trên 2 tín hiệu
            volume_score = min(0.6, 0.4 * (icmp_count / self._threshold)) if volume_triggered else 0.1
            payload_score = min(0.5, 0.4 * (large_payload_count / max(self._threshold * 0.3, 1))) if payload_triggered else 0.1
            confidence = min(0.99, volume_score + payload_score)

            dst_ip = dst_ip_map.get(src_ip, "unknown")

            # Severity dựa trên mức độ tổng hợp
            if confidence >= 0.8:
                severity = "high"
            elif confidence >= 0.6:
                severity = "medium"
            else:
                severity = "low"

            alerts.append(Alert(
                id=0,
                ruleName=self.ruleName,
                attackType="ICMP Tunnel",
                sourceIp=src_ip,
                destinationIp=dst_ip,
                severity=severity,
                confidence=round(confidence, 4),
                timestamp=traffic.endTime or datetime.now(),
                description=(
                    f"Phát hiện ICMP Tunneling nghi ngờ từ {src_ip} → {dst_ip}: "
                    f"{icmp_count} gói ICMP (ngưỡng: {self._threshold}), "
                    f"{large_payload_count} gói có payload > {SUSPICIOUS_ICMP_PAYLOAD_SIZE} bytes, "
                    f"payload trung bình: {avg_payload:.1f} bytes. "
                    f"Cửa sổ: {traffic.startTime} → {traffic.endTime}. "
                    f"Có thể kẻ tấn công đang dùng ICMP để bypass firewall."
                )
            ))

        return alerts
