import sys
import os
import json
import unittest
from datetime import datetime

# Adjust path to import models from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from models.packet import Packet

def run_standalone_demo():
    """
    Runs a standalone visual flow of the Packet class functionality,
    printing sample packets and their serialized layouts.
    """
    
    print("          STANDALONE PACKET FLOW & FORMATTING INSPECTOR          ")
    print("=" * 70)
    
    # 1. TCP Packet Example (HTTP Request)
    tcp_packet = Packet(
        id=1,
        timestamp=datetime.now(),
        srcIp="192.168.1.15",
        dstIp="10.0.0.1",
        srcPort=54321,
        dstPort=80,
        protocol="TCP",
        tcpFlags=["SYN" ,"ACK"],
        length=74,
        srcMac="00:11:22:33:44:55",
        dstMac="66:77:88:99:aa:bb",
        ttl=64,
        payload=None,
        interface="eth0"
    )
    
    print("\n[1] --- TCP PACKET ---")
    print("Summary:")
    print(f"  {tcp_packet.getSummary()}")
    print("\nisTCP() Check:")
    print(f"  {tcp_packet.isTCP()}")
    print("\nDictionary Output (JSON format):")
    print(json.dumps(tcp_packet.toDictionary(), indent=2))
    print("-" * 70)

    # 2. UDP Packet Example (DNS Query)
    udp_packet = Packet(
        id=2,
        timestamp=datetime.now(),
        srcIp="192.168.1.15",
        dstIp="8.8.8.8",
        srcPort=58291,
        dstPort=53,
        protocol="UDP",
        tcpFlags=[],
        length=60,
        srcMac="00:11:22:33:44:55",
        dstMac="66:77:88:99:aa:bb",
        ttl=128,
        payload=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07google\x03com\x00\x00\x01\x00\x01",
        interface="eth0"
    )
    
    print("\n[2] --- UDP PACKET ---")
    print("Summary:")
    print(f"  {udp_packet.getSummary()}")
    print("\nisUDP() Check:")
    print(f"  {udp_packet.isUDP()}")
    print("\nDictionary Output (JSON format):")
    print(json.dumps(udp_packet.toDictionary(), indent=2))
    print("-" * 70)

    # 3. ICMP Packet Example (Ping Request)
    icmp_packet = Packet(
        id=3,
        timestamp=datetime.now(),
        srcIp="192.168.1.15",
        dstIp="8.8.8.8",
        srcPort=0,
        dstPort=0,
        protocol="ICMP",
        tcpFlags=[],
        length=42,
        srcMac="00:11:22:33:44:55",
        dstMac="11:22:33:44:55:66",
        ttl=56,
        payload=b"\x08\x00\xf7\xff\x00\x01\x00\x01ping-payload",
        interface="eth0"
    )
    
    print("\n[3] --- ICMP PACKET ---")
    print("Summary:")
    print(f"  {icmp_packet.getSummary()}")
    print("\nisICMP() Check:")
    print(f"  {icmp_packet.isICMP()}")
    print("\nDictionary Output (JSON format):")
    print(json.dumps(icmp_packet.toDictionary(), indent=2))
    print("=" * 70)


class TestPacket(unittest.TestCase):
    """
    Standard unit testing suite for test runner execution.
    """
    def setUp(self):
        self.time_test = datetime(2026, 8, 17, 11, 0, 0)
        self.packet = Packet(
            id=10,
            timestamp=self.time_test,
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
            payload=b"test",
            interface="eth0"
        )
        
    def test_packet_properties(self):
        self.assertEqual(self.packet.id, 10)
        self.assertTrue(self.packet.isTCP())
        self.assertFalse(self.packet.isUDP())
        self.assertFalse(self.packet.isICMP())
        self.assertEqual(
            self.packet.getSummary(),
            "Packet #10 | 2026-08-17 11:00:00.000 | TCP 192.168.1.5:44321 -> 10.0.0.1:80 | Length: 64 bytes | Flags: [SYN]"
        )
        self.assertEqual(self.packet.toDictionary()["payload"], "74657374") # Hex of b"test"

if __name__ == '__main__':
    # If "--unittest" flag is passed or we run through unittest framework
    if len(sys.argv) > 1 and sys.argv[1] == '--unittest':
        sys.argv.pop(1)
        unittest.main()
    else:
        run_standalone_demo()
