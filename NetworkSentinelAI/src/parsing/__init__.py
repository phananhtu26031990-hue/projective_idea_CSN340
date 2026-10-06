"""
Layer 2 – Parsing Layer
========================
PacketParser là lớp trung gian giữa thế giới bên ngoài và hệ thống IDS.
Nó nhận dữ liệu thô (dict hoặc args) và tạo ra Packet object.

Trong kiến trúc đầy đủ:
  Raw PyShark → PySharkAdapter.convert() → Packet

PacketParser hữu ích khi:
  - Xây dựng Packet từ dict (ví dụ: đọc từ JSON log, từ database)
  - Validate dữ liệu đầu vào trước khi tạo Packet
  - Tạo mock packet trong unit test
"""

from .packetParser import PacketParser

__all__ = ["PacketParser"]
