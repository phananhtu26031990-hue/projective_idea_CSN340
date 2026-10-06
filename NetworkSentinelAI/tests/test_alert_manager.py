"""
Test Alert Manager
====================
Kiểm thử AlertManager: thêm, lọc, thống kê, dọn dẹp alert.
"""

import unittest
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from models.alert import Alert
from alert_management.alertManager import AlertManager


def makeAlert(id, attack_type="SYN Flood", severity="critical",
              src_ip="192.168.1.1", confidence=0.95, seconds_ago=0):
    """Factory function tạo Alert nhanh cho test."""
    return Alert(
        id=id,
        ruleName="TestRule",
        attackType=attack_type,
        sourceIp=src_ip,
        destinationIp="10.0.0.1",
        severity=severity,
        confidence=confidence,
        timestamp=datetime.now() - timedelta(seconds=seconds_ago),
        description=f"Test alert #{id}"
    )


class TestAlertManager(unittest.TestCase):

    def setUp(self):
        self.manager = AlertManager()
        # Thêm một số alert mẫu
        self.manager.addAlert(makeAlert(1, "SYN Flood", "critical", "1.1.1.1"))
        self.manager.addAlert(makeAlert(2, "Port Scan", "high", "2.2.2.2"))
        self.manager.addAlert(makeAlert(3, "ACK Flood", "medium", "1.1.1.1"))
        self.manager.addAlert(makeAlert(4, "ICMP Tunnel", "low", "3.3.3.3"))

    def test_add_and_count(self):
        """Kiểm tra thêm alert và đếm."""
        self.assertEqual(len(self.manager), 4)
        self.assertEqual(self.manager.alertCount, 4)

    def test_filter_by_severity(self):
        """Lọc alert theo severity phải chính xác."""
        critical = self.manager.filterBySeverity("critical")
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].attackType, "SYN Flood")

        high = self.manager.filterBySeverity("high")
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].attackType, "Port Scan")

    def test_filter_by_source_ip(self):
        """Lọc theo IP nguồn."""
        from_1_1_1_1 = self.manager.filterBySourceIp("1.1.1.1")
        self.assertEqual(len(from_1_1_1_1), 2)  # SYN Flood và ACK Flood

    def test_filter_by_attack_type(self):
        """Lọc theo loại tấn công."""
        syn_floods = self.manager.filterByAttackType("SYN Flood")
        self.assertEqual(len(syn_floods), 1)

    def test_get_all_sorted(self):
        """getAll() với sort phải trả về critical trước."""
        all_alerts = self.manager.getAll(sorted_by_severity=True)
        self.assertEqual(all_alerts[0].severity, "critical")
        self.assertEqual(all_alerts[-1].severity, "low")

    def test_get_latest(self):
        """getLatest() phải trả về đúng số lượng và đúng thứ tự."""
        latest_2 = self.manager.getLatest(count=2)
        self.assertEqual(len(latest_2), 2)
        # Alert mới nhất là #3 và #4 (theo thứ tự thêm vào)
        self.assertEqual(latest_2[-1].id, 4)

    def test_get_critical_alerts(self):
        """Shortcut getCriticalAlerts() phải hoạt động."""
        criticals = self.manager.getCriticalAlerts()
        self.assertEqual(len(criticals), 1)
        self.assertEqual(criticals[0].severity, "critical")

    def test_severity_count(self):
        """getSeverityCount() phải trả về đúng số lượng."""
        counts = self.manager.getSeverityCount()
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["low"], 1)

    def test_top_source_ips(self):
        """getTopSourceIps() phải trả về IP có nhiều alert nhất."""
        top = self.manager.getTopSourceIps(top_n=1)
        self.assertEqual(len(top), 1)
        # 1.1.1.1 có 2 alert, nhiều nhất
        self.assertEqual(top[0]["ip"], "1.1.1.1")
        self.assertEqual(top[0]["count"], 2)

    def test_get_stats(self):
        """getStats() phải trả về dict đầy đủ."""
        stats = self.manager.getStats()
        self.assertIn("totalAlerts", stats)
        self.assertIn("severityBreakdown", stats)
        self.assertIn("topSourceIps", stats)
        self.assertIn("attackTypes", stats)
        self.assertEqual(stats["totalAlerts"], 4)

    def test_clear(self):
        """clear() phải xóa tất cả alert nhưng giữ counter."""
        old_count = self.manager.alertCount
        self.manager.clear()
        self.assertEqual(len(self.manager), 0)
        # alertCount (tổng cộng nhận) không bị reset
        self.assertEqual(self.manager.alertCount, old_count)

    def test_remove_before(self):
        """removeBefore() phải xóa alert cũ hơn thời điểm cho trước."""
        # Thêm alert cũ (60 giây trước)
        old_alert = makeAlert(99, seconds_ago=60)
        self.manager.addAlert(old_alert)
        self.assertEqual(len(self.manager), 5)

        # Xóa alert cũ hơn 30 giây
        cutoff = datetime.now() - timedelta(seconds=30)
        removed = self.manager.removeBefore(cutoff)
        self.assertEqual(removed, 1)
        self.assertEqual(len(self.manager), 4)

    def test_repr(self):
        """__repr__ phải chứa thông tin hữu ích."""
        repr_str = repr(self.manager)
        self.assertIn("AlertManager", repr_str)
        self.assertIn("critical=1", repr_str)

    def test_add_alerts_batch(self):
        """addAlerts() phải thêm nhiều alert cùng lúc."""
        new_manager = AlertManager()
        batch = [makeAlert(i) for i in range(10)]
        new_manager.addAlerts(batch)
        self.assertEqual(len(new_manager), 10)


if __name__ == "__main__":
    unittest.main()
