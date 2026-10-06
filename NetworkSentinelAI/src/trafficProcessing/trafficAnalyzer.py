from datetime import datetime
from typing import List, Optional
from models.packet import Packet
from models.traffic import Traffic   

class TrafficAnalyzer:
    """
    Quản lý việc phân loại và gom nhóm các gói tin (Packet) thành các cửa sổ
    thời gian (Traffic window) có kích thước cố định (windowSize giây).

    Nguyên lý hoạt động:
    - Mỗi Packet được xử lý qua processPacket()
    - Nếu timestamp của packet vượt quá windowSize kể từ startTime của
      cửa sổ hiện tại → đóng cửa sổ cũ, lưu vào lịch sử, mở cửa sổ mới
    - Giúp tạo ra các "snapshot" traffic theo thời gian để phân tích
    """

    def __init__(self, windowSize: int = 10):
        """
        Khởi tạo TrafficAnalyzer với kích thước cửa sổ thời gian.

        Args:
            windowSize (int): Kích thước cửa sổ tính bằng giây. Mặc định 10 giây.
        """
        self.windowSize: int = windowSize                   # Kích thước cửa sổ thời gian (giây)
        self.trafficHistory: List[Traffic] = []             # Danh sách các traffic window đã đóng
        self.currentTraffic: Traffic = Traffic()            # Cửa sổ traffic hiện tại đang hoạt động

    def createNewTraffic(self) -> Traffic:
        """
        Tạo một cửa sổ Traffic mới và gán nó là cửa sổ hiện tại.

        Returns:
            Traffic: Cửa sổ Traffic mới rỗng.
        """
        self.currentTraffic = Traffic()
        return self.currentTraffic

    def getCurrentTraffic(self) -> Traffic:
        """
        Trả về cửa sổ Traffic đang hoạt động hiện tại.

        Returns:
            Traffic: Cửa sổ Traffic hiện tại.
        """
        return self.currentTraffic

    def isWindowExpired(self, packet: Optional[Packet] = None) -> bool:
        """
        Kiểm tra xem cửa sổ traffic hiện tại đã hết hạn chưa.

        Logic:
        - Nếu chưa có packet nào trong cửa sổ (startTime = None) → chưa hết hạn
        - Nếu có packet: so sánh timestamp của packet (hoặc datetime.now()) với startTime
        - Nếu chênh lệch >= windowSize → hết hạn

        Args:
            packet (Optional[Packet]): Gói tin đang xét. Nếu None → dùng thời gian thực.

        Returns:
            bool: True nếu cửa sổ đã hết hạn.
        """
        # Chưa có packet nào trong cửa sổ → chưa thể hết hạn
        if not self.currentTraffic or self.currentTraffic.startTime is None:
            return False

        # Dùng timestamp của packet nếu có, ngược lại dùng thời gian thực
        referenceTime = packet.timestamp if packet is not None else datetime.now()

        # Tính thời gian đã trôi qua kể từ đầu cửa sổ
        duration = (referenceTime - self.currentTraffic.startTime).total_seconds()

        return duration >= self.windowSize

    def closeTraffic(self) -> Traffic:
        """
        Đóng cửa sổ Traffic hiện tại: lưu vào lịch sử và trả về cửa sổ đã đóng.

        Returns:
            Traffic: Cửa sổ Traffic vừa được đóng.
        """
        closedTraffic = self.currentTraffic
        self.trafficHistory.append(closedTraffic)       # Lưu vào lịch sử
        return closedTraffic

    def processPacket(self, packet: Packet) -> Optional[Traffic]:
        """
        Xử lý một gói tin đến:
        1. Kiểm tra cửa sổ hiện tại có hết hạn không
        2. Nếu hết hạn → đóng cửa sổ cũ, tạo cửa sổ mới, trả về cửa sổ đã đóng
        3. Thêm packet vào cửa sổ hiện tại

        Args:
            packet (Packet): Gói tin cần xử lý.

        Returns:
            Optional[Traffic]: Cửa sổ Traffic vừa đóng (nếu có), None nếu chưa đóng.
        """
        closedTraffic = None

        if self.isWindowExpired(packet):
            closedTraffic = self.closeTraffic()     # Đóng cửa sổ cũ, lưu vào history
            self.createNewTraffic()                  # Mở cửa sổ mới

        self.currentTraffic.addPacket(packet)        # Thêm packet vào cửa sổ hiện tại
        return closedTraffic                         # Trả về cửa sổ đã đóng để xử lý tiếp (detection, logging...)
