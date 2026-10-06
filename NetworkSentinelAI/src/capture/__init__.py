"""
Layer 1 – Capture Layer
=======================
Chịu trách nhiệm bắt gói tin thô từ card mạng thông qua thư viện PyShark
(wrapper của TShark/Wireshark).

Thứ tự gọi:
  PacketCapture → gọi startCapture() → dùng PySharkAdapter để chuyển đổi
  mỗi raw packet PyShark → Packet object → gọi callback để pipeline tiếp tục
"""

from .packetCapture import PacketCapture
from .pysharkAdapter import PySharkAdapter

__all__ = ["PacketCapture", "PySharkAdapter"]
