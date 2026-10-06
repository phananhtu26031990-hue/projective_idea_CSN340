"""
Test Detection Rules
=====================
Kiểm thử toàn bộ Detection Layer: RuleEngine và 4 rules phát hiện tấn công.

Chiến lược test:
  - Tạo Traffic window giả lập với các gói tin chủ ý kích hoạt từng rule
  - Kiểm tra rule phát hiện đúng khi vượt ngưỡng
  - Kiểm tra rule KHÔNG phát hiện khi traffic bình thường
  - Kiểm tra RuleEngine chạy tất cả rule và tổng hợp alert
"""

import unittest
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from models.packet import Packet
from models.traffic import Traffic
from detection.rules.syn_flood.synFloodRule import SynFloodRule
from detection.rules.ack_flood.ackFloodRule import AckFloodRule
from detection.rules.port_scan.portScanRule import PortScanRule
from detection.rules.icmp_tunnel.icmpTunnelRule import ICMPTunnelRule
from detection.ruleEngine import RuleEngine


def makePacket(
    srcIp, dstIp, protocol, flags=None, dstPort=80, srcPort=50000,
    length=64, payload=b"", offset_seconds=0
):
    """Factory function tạo Packet nhanh cho test."""
    return Packet(
        id=0,
        timestamp=datetime(2026, 8, 19, 12, 0, 0) + timedelta(seconds=offset_seconds),
        srcIp=srcIp,
        dstIp=dstIp,
        srcPort=srcPort,
        dstPort=dstPort,
        protocol=protocol,
        tcpFlags=flags or [],
        length=length,
        srcMac="00:11:22:33:44:55",
        dstMac="66:77:88:99:aa:bb",
        ttl=64,
        payload=payload,
        interface="eth0"
    )


def buildTraffic(packets):
    """Tạo Traffic window từ danh sách packet."""
    traffic = Traffic()
    for p in packets:
        traffic.addPacket(p)
    return traffic


class TestSynFloodRule(unittest.TestCase):

    def setUp(self):
        self.rule = SynFloodRule(threshold=10.0)  # Ngưỡng thấp để test dễ

    def test_detect_syn_flood(self):
        """Phải phát hiện khi 1 IP gửi > threshold gói SYN."""
        packets = []
        for i in range(15):  # 15 gói SYN > threshold 10
            packets.append(makePacket(
                srcIp="192.168.1.100",
                dstIp="10.0.0.1",
                protocol="TCP",
                flags=["SYN"],
                srcPort=40000 + i,
                offset_seconds=i * 0.1
            ))
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].sourceIp, "192.168.1.100")
        self.assertEqual(alerts[0].attackType, "SYN Flood")
        self.assertEqual(alerts[0].severity, "critical")
        self.assertGreater(alerts[0].confidence, 0.7)

    def test_no_alert_below_threshold(self):
        """Không phát hiện khi SYN count < threshold."""
        packets = []
        for i in range(5):  # 5 gói < threshold 10
            packets.append(makePacket(
                srcIp="192.168.1.1",
                dstIp="10.0.0.1",
                protocol="TCP",
                flags=["SYN"],
                srcPort=40000 + i,
            ))
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)
        self.assertEqual(len(alerts), 0)

    def test_syn_ack_not_counted(self):
        """SYN-ACK (phản hồi bình thường) không được đếm là SYN Flood."""
        packets = []
        for i in range(20):  # 20 gói SYN-ACK → không phải flood
            packets.append(makePacket(
                srcIp="10.0.0.1",
                dstIp="192.168.1.1",
                protocol="TCP",
                flags=["SYN", "ACK"],  # SYN-ACK = phản hồi server, không phải attack
                srcPort=80,
                dstPort=40000 + i,
            ))
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)
        self.assertEqual(len(alerts), 0)  # Không có alert vì đây là SYN-ACK, không phải SYN flood

    def test_empty_traffic(self):
        """Traffic rỗng không tạo alert."""
        traffic = Traffic()
        alerts = self.rule.analyze(traffic)
        self.assertEqual(len(alerts), 0)


class TestAckFloodRule(unittest.TestCase):

    def setUp(self):
        self.rule = AckFloodRule(threshold=10.0)

    def test_detect_ack_flood(self):
        """Phải phát hiện khi 1 IP gửi > threshold gói ACK."""
        packets = []
        for i in range(15):
            packets.append(makePacket(
                srcIp="172.16.0.5",
                dstIp="10.0.0.2",
                protocol="TCP",
                flags=["ACK"],
                srcPort=50000 + i,
            ))
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)

        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attackType, "ACK Flood")
        self.assertEqual(alerts[0].sourceIp, "172.16.0.5")

    def test_no_alert_below_threshold(self):
        """Không phát hiện khi ACK count < threshold."""
        packets = [
            makePacket("10.0.0.1", "10.0.0.2", "TCP", ["ACK"], offset_seconds=i)
            for i in range(5)
        ]
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)
        self.assertEqual(len(alerts), 0)


class TestPortScanRule(unittest.TestCase):

    def setUp(self):
        self.rule = PortScanRule(threshold=10.0)

    def test_detect_port_scan(self):
        """Phát hiện khi 1 IP quét > threshold port khác nhau."""
        packets = []
        for port in range(1, 20):  # Quét 19 port khác nhau > threshold 10
            packets.append(makePacket(
                srcIp="10.100.0.1",
                dstIp="192.168.1.254",
                protocol="TCP",
                flags=["SYN"],
                dstPort=port,
                offset_seconds=port * 0.1
            ))
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)

        self.assertGreaterEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.attackType, "Port Scan")
        self.assertEqual(alert.sourceIp, "10.100.0.1")

    def test_no_alert_same_port(self):
        """Nhiều gói đến cùng 1 port → không phải port scan."""
        packets = [
            makePacket("10.0.0.1", "10.0.0.2", "TCP", ["SYN"], dstPort=80)
            for _ in range(20)
        ]
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)
        self.assertEqual(len(alerts), 0)

    def test_severity_increases_with_port_count(self):
        """Severity phải phản ánh mức độ nghiêm trọng."""
        # 200 port → high severity
        packets = [
            makePacket("10.1.1.1", "192.168.0.1", "TCP", ["SYN"], dstPort=p)
            for p in range(1, 201)
        ]
        traffic = buildTraffic(packets)
        rule = PortScanRule(threshold=5.0)
        alerts = rule.analyze(traffic)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertIn(alerts[0].severity, ["high", "critical"])


class TestICMPTunnelRule(unittest.TestCase):

    def setUp(self):
        self.rule = ICMPTunnelRule(threshold=10.0)

    def test_detect_high_icmp_volume(self):
        """Phát hiện khi số gói ICMP vượt ngưỡng."""
        packets = []
        for i in range(15):  # 15 gói ICMP > threshold 10
            packets.append(makePacket(
                srcIp="10.0.0.99",
                dstIp="8.8.8.8",
                protocol="ICMP",
                offset_seconds=i * 0.2
            ))
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)

        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attackType, "ICMP Tunnel")

    def test_detect_large_payload(self):
        """Phát hiện khi payload ICMP lớn bất thường (> 100 bytes)."""
        large_payload = b"X" * 500  # 500 bytes payload - bất thường
        packets = []
        for i in range(15):
            packets.append(makePacket(
                srcIp="10.0.0.50",
                dstIp="8.8.4.4",
                protocol="ICMP",
                payload=large_payload,
                length=500
            ))
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)
        self.assertGreaterEqual(len(alerts), 1)

    def test_normal_ping_no_alert(self):
        """Ping bình thường (ít gói, payload nhỏ) không tạo alert."""
        small_payload = b"A" * 32  # 32 bytes - bình thường
        packets = [
            makePacket("192.168.1.1", "8.8.8.8", "ICMP",
                       payload=small_payload, length=40)
            for _ in range(5)  # 5 gói < threshold 10
        ]
        traffic = buildTraffic(packets)
        alerts = self.rule.analyze(traffic)
        self.assertEqual(len(alerts), 0)


class TestRuleEngine(unittest.TestCase):

    def test_engine_runs_all_rules(self):
        """RuleEngine phải chạy tất cả rules và tổng hợp kết quả."""
        config = {
            "rules": {
                "syn_flood": {"threshold": 5.0},
                "ack_flood": {"threshold": 5.0},
                "port_scan": {"threshold": 5.0},
                "icmp_tunnel": {"threshold": 5.0},
            }
        }
        engine = RuleEngine(config=config)

        # Tạo traffic với SYN flood VÀ port scan cùng lúc
        packets = []

        # SYN Flood từ IP A
        for i in range(10):
            packets.append(makePacket("1.1.1.1", "2.2.2.2", "TCP", ["SYN"], srcPort=1000+i))

        # Port Scan từ IP B
        for port in range(1, 10):
            packets.append(makePacket("3.3.3.3", "2.2.2.2", "TCP", ["SYN"], dstPort=port))

        traffic = buildTraffic(packets)
        alerts = engine.analyze(traffic)

        # Phải có ít nhất 2 alert (1 SYN flood + 1 port scan)
        self.assertGreaterEqual(len(alerts), 2)

        # Tất cả alert phải có ID được gán
        for alert in alerts:
            self.assertGreater(alert.id, 0)

    def test_engine_handles_rule_error_gracefully(self):
        """Nếu 1 rule lỗi, các rule khác vẫn chạy."""
        from unittest.mock import MagicMock, patch
        from detection.ruleInterface import Rule

        # Tạo mock rule bị lỗi
        broken_rule = MagicMock(spec=Rule)
        broken_rule.ruleName = "BrokenRule"
        broken_rule.analyze.side_effect = RuntimeError("Simulated crash")

        engine = RuleEngine.__new__(RuleEngine)
        engine.alertCounter = 0

        # Thêm rule bình thường và rule bị lỗi
        working_rule = SynFloodRule(threshold=5.0)
        engine.rules = [broken_rule, working_rule]

        packets = [
            makePacket("1.1.1.1", "2.2.2.2", "TCP", ["SYN"], srcPort=1000+i)
            for i in range(10)
        ]
        traffic = buildTraffic(packets)

        # Không nên raise exception, vẫn trả về alert từ working_rule
        alerts = engine.analyze(traffic)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attackType, "SYN Flood")


if __name__ == "__main__":
    unittest.main()
