"""
PacketCapture – Layer 1: Capture Layer
=======================================
Bắt gói tin trực tiếp từ card mạng thông qua PyShark (TShark/Wireshark).

Thiết kế:
  - Hỗ trợ cả Live Capture (từ card mạng thật) và File Capture (từ file .pcap)
  - Dùng callback pattern: mỗi packet bắt được → gọi on_packet_callback()
  - Cho phép chạy và dừng capture một cách clean

Cách dùng:
    capture = PacketCapture(interface="Ethernet", bpf_filter="tcp")
    capture.startCapture(callback=my_handler)
    # ... sau đó
    capture.stopCapture()
"""

import logging
import sys
import os
from typing import Callable, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.packet import Packet
from capture.pysharkAdapter import PySharkAdapter

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Bắt gói tin từ card mạng và chuyển đổi sang Packet object thông qua PySharkAdapter.

    Attributes:
        interface (str): Tên card mạng (ví dụ: "Ethernet", "eth0", "Wi-Fi")
        bpfFilter (str): BPF filter expression (ví dụ: "tcp", "ip", "port 80")
        isCapturing (bool): Trạng thái đang bắt gói tin hay không
    """

    def __init__(self, interface: str = "eth0", bpfFilter: str = "ip"):
        """
        Args:
            interface (str): Tên card mạng cần monitor.
            bpfFilter (str): BPF filter (Berkeley Packet Filter) để lọc loại gói tin.
        """
        self.interface = interface
        self.bpfFilter = bpfFilter
        self.isCapturing = False
        self._capture = None        # PyShark capture object

    def startCapture(self, callback: Callable[[Packet], None], packet_count: int = 0) -> None:
        """
        Bắt đầu live capture trên interface đã cấu hình.
        Với mỗi gói tin bắt được, chuyển đổi và gọi callback.

        Thiết kế callback pattern:
          - PacketCapture không cần biết làm gì với packet
          - Nó chỉ "thông báo" cho pipeline bằng callback
          - Pipeline (main.py) quyết định xử lý gì tiếp theo

        Args:
            callback: Hàm nhận Packet object. Ví dụ: analyzer.processPacket
            packet_count: Số lượng packet tối đa (0 = vô hạn)
        """
        try:
            import pyshark
        except ImportError:
            logger.error("PyShark chưa được cài đặt. Chạy: pip install pyshark")
            raise

        logger.info(f"Bắt đầu capture trên interface '{self.interface}' với filter '{self.bpfFilter}'")
        self.isCapturing = True

        try:
            self._capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=self.bpfFilter
            )

            for raw_packet in self._capture.sniff_continuously(packet_count=packet_count):
                if not self.isCapturing:
                    break

                try:
                    # Chuyển đổi PyShark packet → Packet model nội bộ
                    packet = PySharkAdapter.convert(raw_packet, interface=self.interface)
                    callback(packet)
                except Exception as e:
                    # Lỗi xử lý 1 packet không dừng toàn bộ capture
                    logger.warning(f"Lỗi xử lý gói tin #{PySharkAdapter._packet_counter}: {e}")
                    continue

        except KeyboardInterrupt:
            logger.info("Capture dừng bởi người dùng (Ctrl+C)")
        finally:
            self.stopCapture()

    def startFileCapture(self, pcap_file: str, callback: Callable[[Packet], None]) -> None:
        """
        Đọc và xử lý gói tin từ file .pcap (dùng cho testing hoặc phân tích offline).

        Args:
            pcap_file (str): Đường dẫn đến file .pcap
            callback: Hàm nhận Packet object
        """
        try:
            import pyshark
        except ImportError:
            logger.error("PyShark chưa được cài đặt. Chạy: pip install pyshark")
            raise

        logger.info(f"Đọc gói tin từ file: {pcap_file}")
        self.isCapturing = True

        try:
            cap = pyshark.FileCapture(pcap_file, display_filter=self.bpfFilter)
            for raw_packet in cap:
                if not self.isCapturing:
                    break
                try:
                    packet = PySharkAdapter.convert(raw_packet, interface="file")
                    callback(packet)
                except Exception as e:
                    logger.warning(f"Lỗi xử lý gói tin từ file: {e}")
                    continue
            cap.close()
        finally:
            self.isCapturing = False
            logger.info("Đọc file capture hoàn tất.")

    def stopCapture(self) -> None:
        """
        Dừng quá trình capture đang chạy.
        """
        self.isCapturing = False
        if self._capture:
            try:
                self._capture.close()
            except Exception:
                pass
            self._capture = None
        logger.info("Capture đã dừng.")
