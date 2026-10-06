"""
LogFormatter Interface (ABC)
==============================
Interface chung cho tất cả các formatter ghi log.

Triết lý:
  Logger không biết và không cần biết dữ liệu được ghi như thế nào.
  Nó chỉ gọi formatter.write(alert).
  Mỗi formatter tự quyết định cách format và ghi.
"""

import sys
import os
from abc import ABC, abstractmethod

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert


class LogFormatter(ABC):
    """
    Interface cho tất cả log formatter.
    Mỗi formatter con phải implement write() và setup().
    """

    @abstractmethod
    def setup(self) -> None:
        """
        Khởi tạo tài nguyên cần thiết (tạo file, bảng DB, ghi header...).
        Được gọi một lần duy nhất khi hệ thống khởi động.
        """
        pass

    @abstractmethod
    def write(self, alert: Alert) -> None:
        """
        Ghi một Alert vào storage.

        Args:
            alert (Alert): Alert cần ghi
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """
        Đóng tài nguyên (flush buffer, đóng file, đóng DB connection...).
        Được gọi khi hệ thống tắt.
        """
        pass
