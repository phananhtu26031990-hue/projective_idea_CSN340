import unittest
import sys
import os
from datetime import datetime, timedelta

# Adjust path to import modules from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from models import Packet, Traffic
from trafficProcessing import TrafficAnalyzer

class TestTrafficAnalyzer(unittest.TestCase):
    
    def setUp(self):
        self.time_now = datetime(2026, 8, 18, 12, 0, 0)
        self.window_size = 5  # 5 seconds
        self.analyzer = TrafficAnalyzer(windowSize=self.window_size)
        
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
            payload=b"TCP packet 1",
            interface="eth0"
        )
        
        self.packet_2 = Packet(
            id=2,
            timestamp=self.time_now + timedelta(seconds=2),
            srcIp="192.168.1.10",
            dstIp="10.0.0.1",
            srcPort=55123,
            dstPort=80,
            protocol="TCP",
            tcpFlags=["ACK"],
            length=128,
            srcMac="00:11:22:33:44:cc",
            dstMac="66:77:88:99:aa:bb",
            ttl=64,
            payload=b"TCP packet 2",
            interface="eth0"
        )

        self.packet_3 = Packet(
            id=3,
            timestamp=self.time_now + timedelta(seconds=5),  # 5 seconds later (boundary)
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
            payload=b"ICMP packet",
            interface="eth0"
        )

    def test_initialization(self):
        self.assertEqual(self.analyzer.windowSize, self.window_size)
        self.assertEqual(len(self.analyzer.trafficHistory), 0)
        self.assertIsNotNone(self.analyzer.currentTraffic)
        self.assertEqual(self.analyzer.currentTraffic.totalPackets, 0)

    def test_process_packet_within_window(self):
        # Process first packet
        self.analyzer.processPacket(self.packet_1)
        self.assertEqual(self.analyzer.currentTraffic.totalPackets, 1)
        self.assertEqual(self.analyzer.currentTraffic.startTime, self.time_now)
        
        # Process second packet within 5 seconds window (diff = 2 seconds)
        self.analyzer.processPacket(self.packet_2)
        self.assertEqual(self.analyzer.currentTraffic.totalPackets, 2)
        self.assertEqual(len(self.analyzer.trafficHistory), 0)

    def test_process_packet_expires_window(self):
        # Process first packet (sets startTime to 12:00:00)
        self.analyzer.processPacket(self.packet_1)
        
        # Process second packet (sets endTime to 12:00:02)
        self.analyzer.processPacket(self.packet_2)
        
        # Process third packet (timestamp is 12:00:05, diff = 5 seconds >= windowSize)
        self.analyzer.processPacket(self.packet_3)
        
        # The window should have expired and rotated
        self.assertEqual(len(self.analyzer.trafficHistory), 1)
        closed_traffic = self.analyzer.trafficHistory[0]
        self.assertEqual(closed_traffic.totalPackets, 2)
        self.assertEqual(closed_traffic.startTime, self.time_now)
        self.assertEqual(closed_traffic.endTime, self.time_now + timedelta(seconds=2))
        
        # The new currentTraffic should contain only the third packet
        self.assertEqual(self.analyzer.currentTraffic.totalPackets, 1)
        self.assertEqual(self.analyzer.currentTraffic.startTime, self.packet_3.timestamp)
        self.assertEqual(self.analyzer.currentTraffic.endTime, self.packet_3.timestamp)

    def test_is_window_expired_no_packet(self):
        # Without any packet processed, window is not expired
        self.assertFalse(self.analyzer.isWindowExpired())
        
        # Process a packet to set startTime
        self.analyzer.processPacket(self.packet_1)
        
        # Modifying currentTraffic startTime to be far in the past to trigger expiration manually
        self.analyzer.currentTraffic.startTime = datetime.now() - timedelta(seconds=self.window_size + 1)
        self.assertTrue(self.analyzer.isWindowExpired())

    def test_close_traffic_and_create_new(self):
        self.analyzer.processPacket(self.packet_1)
        old_traffic = self.analyzer.getCurrentTraffic()
        
        closed = self.analyzer.closeTraffic()
        self.assertIs(closed, old_traffic)
        self.assertEqual(len(self.analyzer.trafficHistory), 1)
        self.assertIs(self.analyzer.trafficHistory[0], old_traffic)
        
        new_traffic = self.analyzer.createNewTraffic()
        self.assertIsNot(new_traffic, old_traffic)
        self.assertIs(self.analyzer.getCurrentTraffic(), new_traffic)

if __name__ == '__main__':
    sys.exit(unittest.main())
