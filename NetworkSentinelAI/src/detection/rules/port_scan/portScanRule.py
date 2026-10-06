"""
PortScanRule – Phát hiện Port Scanning
========================================
Port Scan là kỹ thuật do thám mạng: kẻ tấn công thử kết nối đến nhiều port
khác nhau trên target để tìm port nào đang mở (dịch vụ nào đang chạy).

Các loại Port Scan phổ biến:
  - TCP SYN Scan (Half-open): Gửi SYN, nhận SYN-ACK → port mở, gửi RST ngay
  - TCP Connect Scan: Kết nối đầy đủ
  - UDP Scan: Gửi UDP đến nhiều port
  - XMAS Scan: Gửi TCP với nhiều flag bật (FIN, PSH, URG)

Logic phát hiện:
  - Theo dõi: từ 1 IP nguồn, nó kết nối đến bao nhiêu PORT ĐÍch KHÁC NHAU?
  - Bình thường: 1 user thường chỉ kết nối đến 1-5 port (80, 443, 22...)
  - Tấn công: 1 IP quét 50+ port khác nhau trong vài giây

Ngưỡng mặc định: 50 port khác nhau / window
"""

import sys
import os
from datetime import datetime
from typing import List, Dict, Set
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
from models.traffic import Traffic
from models.alert import Alert
from detection.ruleInterface import Rule


class PortScanRule(Rule):
    """
    Rule phát hiện Port Scanning dựa trên số lượng port đích khác nhau mà 1 IP quét.
    """

    def __init__(self, threshold: float = 50.0):
        """
        Args:
            threshold (float): Số lượng port đích khác nhau tối đa từ 1 IP trong 1 window.
        """
        self._threshold = threshold

    @property
    def ruleName(self) -> str:
        return "PortScanDetection"

    def analyze(self, traffic: Traffic) -> List[Alert]:
        """
        Phân tích traffic để phát hiện Port Scan.

        Thuật toán:
          1. Với mỗi IP nguồn, tập hợp tất cả (dstIp, dstPort) mà nó gửi đến
          2. Đếm số port đích KHÁC NHAU (unique destination ports) trên mỗi target IP
          3. Nếu số port đích từ 1 IP nguồn >= threshold → alert

        Args:
            traffic (Traffic): Cửa sổ traffic cần phân tích

        Returns:
            List[Alert]: Danh sách Alert phát hiện được
        """
        # src_ip → { dst_ip → set(dst_ports) }
        scan_map: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))

        for packet in traffic.packets:
            # Port scan thường dùng TCP hoặc UDP
            if packet.isTCP() or packet.isUDP():
                if packet.dstPort > 0:  # Loại bỏ port 0 (không hợp lệ)
                    scan_map[packet.srcIp][packet.dstIp].add(packet.dstPort)

        alerts: List[Alert] = []

        for src_ip, targets in scan_map.items():
            for dst_ip, ports in targets.items():
                unique_port_count = len(ports)

                if unique_port_count >= self._threshold:
                    # Confidence: nhiều port hơn ngưỡng → confidence cao hơn
                    confidence = min(0.99, 0.75 + (unique_port_count - self._threshold) / (self._threshold * 2))

                    # Phân loại severity:
                    # >= 1000 port: Rất nguy hiểm
                    # >= 200 port: Nghiêm trọng
                    # >= threshold: Đáng ngờ
                    if unique_port_count >= 1000:
                        severity = "critical"
                    elif unique_port_count >= 200:
                        severity = "high"
                    else:
                        severity = "medium"

                    # Lấy một số port mẫu để đưa vào mô tả
                    sample_ports = sorted(list(ports))[:10]
                    ports_preview = ", ".join(map(str, sample_ports))
                    if unique_port_count > 10:
                        ports_preview += f"... (và {unique_port_count - 10} port khác)"

                    alerts.append(Alert(
                        id=0,
                        ruleName=self.ruleName,
                        attackType="Port Scan",
                        sourceIp=src_ip,
                        destinationIp=dst_ip,
                        severity=severity,
                        confidence=round(confidence, 4),
                        timestamp=traffic.endTime or datetime.now(),
                        description=(
                            f"Phát hiện Port Scan từ {src_ip} → {dst_ip}: "
                            f"{unique_port_count} port khác nhau bị quét "
                            f"(ngưỡng: {self._threshold}). "
                            f"Cửa sổ: {traffic.startTime} → {traffic.endTime}. "
                            f"Các port bị quét (mẫu): [{ports_preview}]. "
                            f"Kẻ tấn công đang do thám dịch vụ mạng."
                        )
                    ))

        return alerts
