"""
AlertManager – Quản lý Alert
==============================
Trung tâm quản lý vòng đời của tất cả Alert trong hệ thống.

Chức năng:
  1. Lưu trữ (addAlert, addAlerts)
  2. Truy vấn (getAll, filterBySeverity, filterByIp, filterByType)
  3. Thống kê (getStats, getSeverityCount)
  4. Dọn dẹp (clear, removeBefore)

Lý do cần AlertManager:
  - Không phải mọi Alert đều cần xử lý ngay
  - Cần lọc, ưu tiên (critical trước, low sau)
  - Cần thống kê để tạo báo cáo tổng hợp
  - Tránh xử lý duplicate alert
"""

import logging
import sys
import os
from datetime import datetime
from typing import List, Optional, Dict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert

logger = logging.getLogger(__name__)

# Thứ tự ưu tiên severity (thấp = ưu tiên cao hơn)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class AlertManager:
    """
    Quản lý danh sách Alert trong hệ thống IDS.

    Attributes:
        _alerts (List[Alert]): Danh sách nội bộ tất cả alert
        alertCount (int): Tổng số alert đã nhận (kể cả đã xóa)
    """

    def __init__(self):
        self._alerts: List[Alert] = []
        self.alertCount: int = 0

    # ────────────────────────────────────────────────────────
    # THÊM ALERT
    # ────────────────────────────────────────────────────────

    def addAlert(self, alert: Alert) -> None:
        """
        Thêm một Alert vào danh sách quản lý.

        Args:
            alert (Alert): Alert cần thêm
        """
        self._alerts.append(alert)
        self.alertCount += 1
        logger.info(f"Alert mới: [{alert.severity.upper()}] {alert.attackType} từ {alert.sourceIp}")

    def addAlerts(self, alerts: List[Alert]) -> None:
        """
        Thêm nhiều Alert cùng lúc.

        Args:
            alerts (List[Alert]): Danh sách Alert cần thêm
        """
        for alert in alerts:
            self.addAlert(alert)

    # ────────────────────────────────────────────────────────
    # TRUY VẤN
    # ────────────────────────────────────────────────────────

    def getAll(self, sorted_by_severity: bool = True) -> List[Alert]:
        """
        Trả về tất cả alert, có thể sắp xếp theo mức độ nghiêm trọng.

        Args:
            sorted_by_severity (bool): Nếu True, critical → low

        Returns:
            List[Alert]: Danh sách Alert
        """
        if sorted_by_severity:
            return sorted(
                self._alerts,
                key=lambda a: SEVERITY_ORDER.get(a.severity.lower(), 99)
            )
        return list(self._alerts)

    def filterBySeverity(self, severity: str) -> List[Alert]:
        """
        Lọc alert theo mức độ nghiêm trọng.

        Args:
            severity (str): "critical", "high", "medium", hoặc "low"

        Returns:
            List[Alert]: Alert có severity khớp
        """
        return [a for a in self._alerts if a.severity.lower() == severity.lower()]

    def filterBySourceIp(self, ip: str) -> List[Alert]:
        """
        Lấy tất cả alert từ một IP nguồn cụ thể.

        Args:
            ip (str): IP nguồn cần lọc

        Returns:
            List[Alert]: Danh sách Alert từ IP đó
        """
        return [a for a in self._alerts if a.sourceIp == ip]

    def filterByAttackType(self, attack_type: str) -> List[Alert]:
        """
        Lọc alert theo loại tấn công.

        Args:
            attack_type (str): Ví dụ "SYN Flood", "Port Scan"

        Returns:
            List[Alert]: Danh sách Alert khớp
        """
        return [a for a in self._alerts if a.attackType.lower() == attack_type.lower()]

    def getLatest(self, count: int = 10) -> List[Alert]:
        """
        Lấy N alert mới nhất (theo thứ tự thêm vào).

        Args:
            count (int): Số lượng alert cần lấy

        Returns:
            List[Alert]: N alert mới nhất
        """
        return self._alerts[-count:]

    def getCriticalAlerts(self) -> List[Alert]:
        """Shortcut: lấy tất cả critical alert."""
        return self.filterBySeverity("critical")

    # ────────────────────────────────────────────────────────
    # THỐNG KÊ
    # ────────────────────────────────────────────────────────

    def getSeverityCount(self) -> Dict[str, int]:
        """
        Đếm số lượng alert theo từng mức severity.

        Returns:
            Dict[str, int]: {'critical': 5, 'high': 3, 'medium': 2, 'low': 1}
        """
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in self._alerts:
            key = alert.severity.lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    def getTopSourceIps(self, top_n: int = 5) -> List[Dict]:
        """
        Lấy top N IP nguồn gây ra nhiều alert nhất.

        Args:
            top_n (int): Số lượng IP cần lấy

        Returns:
            List[Dict]: [{"ip": "...", "count": 10}, ...]
        """
        ip_counts: Dict[str, int] = {}
        for alert in self._alerts:
            ip_counts[alert.sourceIp] = ip_counts.get(alert.sourceIp, 0) + 1

        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "count": count} for ip, count in sorted_ips[:top_n]]

    def getStats(self) -> Dict:
        """
        Tạo bảng thống kê tổng hợp về tất cả alert.

        Returns:
            Dict: Thống kê đầy đủ
        """
        return {
            "totalAlerts": len(self._alerts),
            "totalAlertCount": self.alertCount,
            "severityBreakdown": self.getSeverityCount(),
            "topSourceIps": self.getTopSourceIps(),
            "attackTypes": list({a.attackType for a in self._alerts}),
        }

    # ────────────────────────────────────────────────────────
    # DỌN DẸP
    # ────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Xóa tất cả alert khỏi danh sách (không reset bộ đếm)."""
        self._alerts.clear()
        logger.info("AlertManager: Đã xóa tất cả alert")

    def removeBefore(self, cutoff_time: datetime) -> int:
        """
        Xóa alert cũ hơn một thời điểm nhất định.

        Args:
            cutoff_time (datetime): Alert trước thời điểm này sẽ bị xóa

        Returns:
            int: Số alert đã xóa
        """
        before = len(self._alerts)
        self._alerts = [a for a in self._alerts if a.timestamp >= cutoff_time]
        removed = before - len(self._alerts)
        if removed > 0:
            logger.info(f"AlertManager: Đã xóa {removed} alert cũ trước {cutoff_time}")
        return removed

    def __len__(self) -> int:
        return len(self._alerts)

    def __repr__(self) -> str:
        stats = self.getSeverityCount()
        return (f"AlertManager(total={len(self._alerts)}, "
                f"critical={stats['critical']}, high={stats['high']}, "
                f"medium={stats['medium']}, low={stats['low']})")
