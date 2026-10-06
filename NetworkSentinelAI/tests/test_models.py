import unittest
import sys
import os
from datetime import datetime, timedelta

# Adjust path to import models from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from models import Packet, Traffic, Alert, AIResult, Report

class TestModels(unittest.TestCase):
    
    def setUp(self):
        self.time_now = datetime(2026, 8, 17, 10, 0, 0)
        self.packet_1 = Packet(
            id=1,
            timestamp=self.time_now,
            srcIp="192.168.1.5",
            dstIp="10.0.0.1",
            srcPort=44321,
            dstPort=80,
            protocol="TCP",
            tcpFlags=["SYN"],
            length=64,
            srcMac="00:11:22:33:44:55",
            dstMac="66:77:88:99:aa:bb",
            ttl=64,
            payload=b"GET / HTTP/1.1\r\n\r\n",
            interface="eth0"
        )
        
        self.packet_2 = Packet(
            id=2,
            timestamp=self.time_now + timedelta(seconds=2),
            srcIp="192.168.1.10",
            dstIp="10.0.0.1",
            srcPort=55123,
            dstPort=53,
            protocol="UDP",
            tcpFlags=[],
            length=128,
            srcMac="00:11:22:33:44:cc",
            dstMac="66:77:88:99:aa:bb",
            ttl=128,
            payload=b"\x00\x01dns-query",
            interface="eth0"
        )

        self.packet_3 = Packet(
            id=3,
            timestamp=self.time_now + timedelta(seconds=4),
            srcIp="192.168.1.5",
            dstIp="8.8.8.8",
            srcPort=0,
            dstPort=0,
            protocol="ICMP",
            tcpFlags=[],
            length=32,
            srcMac="00:11:22:33:44:55",
            dstMac="11:22:33:44:55:66",
            ttl=56,
            payload=b"\x08\x00ping",
            interface="eth0"
        )

    def test_packet_methods(self):
        # Test protocol helper checks
        self.assertTrue(self.packet_1.isTCP())
        self.assertFalse(self.packet_1.isUDP())
        self.assertFalse(self.packet_1.isICMP())
        
        self.assertTrue(self.packet_2.isUDP())
        self.assertFalse(self.packet_2.isTCP())
        
        self.assertTrue(self.packet_3.isICMP())
        
        # Test summary format
        summary_tcp = self.packet_1.getSummary()
        self.assertIn("Packet #1", summary_tcp)
        self.assertIn("TCP 192.168.1.5:44321 -> 10.0.0.1:80", summary_tcp)
        self.assertIn("Length: 64 bytes", summary_tcp)
        self.assertIn("Flags: [SYN]", summary_tcp)
        
        summary_icmp = self.packet_3.getSummary()
        self.assertIn("ICMP 192.168.1.5 -> 8.8.8.8", summary_icmp)
        
        # Test toDictionary serialization
        dict_rep = self.packet_1.toDictionary()
        self.assertEqual(dict_rep["id"], 1)
        self.assertEqual(dict_rep["srcIp"], "192.168.1.5")
        self.assertEqual(dict_rep["protocol"], "TCP")
        self.assertEqual(dict_rep["payload"], "474554202f20485454502f312e310d0a0d0a")  # Hex encoded payload
        self.assertEqual(dict_rep["timestamp"], self.time_now.isoformat())

    def test_traffic_aggregation(self):
        traffic = Traffic()
        self.assertEqual(traffic.totalPackets, 0)
        self.assertEqual(traffic.totalByte, 0)
        self.assertIsNone(traffic.startTime)
        self.assertIsNone(traffic.endTime)
        
        # Add packets and verify dynamic updates
        traffic.addPacket(self.packet_1)
        self.assertEqual(traffic.totalPackets, 1)
        self.assertEqual(traffic.totalByte, 64)
        self.assertEqual(traffic.startTime, self.time_now)
        self.assertEqual(traffic.endTime, self.time_now)
        self.assertEqual(traffic.sourceIps, ["192.168.1.5"])
        self.assertEqual(traffic.destinationIps, ["10.0.0.1"])
        
        traffic.addPacket(self.packet_2)
        traffic.addPacket(self.packet_3)
        
        self.assertEqual(traffic.totalPackets, 3)
        self.assertEqual(traffic.totalByte, 64 + 128 + 32)
        self.assertEqual(traffic.startTime, self.time_now)
        self.assertEqual(traffic.endTime, self.time_now + timedelta(seconds=4))
        self.assertEqual(set(traffic.sourceIps), {"192.168.1.5", "192.168.1.10"})
        self.assertEqual(set(traffic.destinationIps), {"10.0.0.1", "8.8.8.8"})
        
        # Calculate rate (3 packets over 4 seconds = 0.75 pps)
        rate = traffic.calculateRate()
        self.assertEqual(rate, 0.75)
        
        # Test stats generation
        stats = traffic.getStatistics()
        self.assertEqual(stats["totalPackets"], 3)
        self.assertEqual(stats["totalByte"], 224)
        self.assertEqual(stats["durationSeconds"], 4.0)
        self.assertEqual(stats["packetRatePps"], 0.75)
        self.assertEqual(stats["byteRateBps"], 224 / 4.0)
        self.assertEqual(stats["protocolCounts"], {"TCP": 1, "UDP": 1, "ICMP": 1})
        self.assertEqual(stats["uniqueSourceIpsCount"], 2)

    def test_alert(self):
        alert = Alert(
            id=101,
            ruleName="SynFloodDetection",
            attackType="SynFlood",
            sourceIp="192.168.1.99",
            destinationIp="10.0.0.1",
            severity="critical",
            confidence=0.95,
            timestamp=self.time_now,
            description="Massive SYN packet spike from single source IP."
        )
        
        self.assertEqual(alert.ruleName, "SynFloodDetection")
        
        message = alert.getMessage()
        self.assertIn("[CRITICAL ALERT #101]", message)
        self.assertIn("SynFlood detected", message)
        self.assertIn("Confidence: 0.95", message)
        
        dict_rep = alert.toDictionary()
        self.assertEqual(dict_rep["id"], 101)
        self.assertEqual(dict_rep["timestamp"], self.time_now.isoformat())
        self.assertEqual(dict_rep["confidence"], 0.95)

    def test_ai_result(self):
        ai_res = AIResult(
            riskLevel="high",
            confidence=0.88,
            explanation="The observed behavior is highly consistent with active reconnaissance.",
            recommendation="Block source IP 192.168.1.99 and review access control policies.",
            timestamp=self.time_now
        )
        
        self.assertEqual(ai_res.riskLevel, "high")
        
        dict_rep = ai_res.toDictionary()
        self.assertEqual(dict_rep["riskLevel"], "high")
        self.assertEqual(dict_rep["confidence"], 0.88)
        self.assertEqual(dict_rep["timestamp"], self.time_now.isoformat())

    def test_report(self):
        # Create alert and AI result
        alert = Alert(
            id=101,
            ruleName="SynFloodDetection",
            attackType="SynFlood",
            sourceIp="192.168.1.99",
            destinationIp="10.0.0.1",
            severity="critical",
            confidence=0.95,
            timestamp=self.time_now,
            description="Massive SYN packet spike."
        )
        
        ai_res = AIResult(
            riskLevel="high",
            confidence=0.88,
            explanation="AI assessment identifies a brute force scanning attempt.",
            recommendation="Restrict ports.",
            timestamp=self.time_now
        )
        
        stats = {
            "totalPackets": 1000,
            "totalByte": 64000,
            "packetRatePps": 20.0
        }
        
        report = Report(
            id="rpt-20260817-001",
            timestamp=self.time_now,
            alerts=[alert],
            aiResult=ai_res,
            statistics=stats,
            summary="Completed network security review."
        )
        
        dict_rep = report.toDictionary()
        self.assertEqual(dict_rep["id"], "rpt-20260817-001")
        self.assertEqual(dict_rep["summary"], "Completed network security review.")
        self.assertEqual(len(dict_rep["alerts"]), 1)
        self.assertEqual(dict_rep["alerts"][0]["id"], 101)
        self.assertEqual(dict_rep["aiResult"]["riskLevel"], "high")
        self.assertEqual(dict_rep["statistics"]["totalPackets"], 1000)

if __name__ == '__main__':
    unittest.main()
