"""
NotificationChannel Interface
================================
Interface chung cho tất cả kênh thông báo.
"""

from abc import ABC, abstractmethod
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert


class NotificationChannel(ABC):
    """Interface cho notification channel."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """
        Gửi thông báo cho alert.

        Args:
            alert (Alert): Alert cần thông báo

        Returns:
            bool: True nếu gửi thành công
        """
        pass

    @abstractmethod
    def isEnabled(self) -> bool:
        """Kiểm tra channel có được bật không."""
        pass
