"""
Layer 8 – Notification Layer
==============================
Gửi thông báo cảnh báo tức thời qua các kênh liên lạc.

Kiến trúc:
  NotificationManager ──── NotificationChannel (Interface)
                                │
                                ├── TelegramChannel
                                └── EmailChannel

Thiết kế:
  - Tương tự Storage Layer: Strategy Pattern
  - Mỗi channel độc lập, lỗi 1 channel không ảnh hưởng kênh khác
  - Chỉ gửi alert có severity >= min_severity (tránh spam)
  - Cấu hình từ config.yaml: bật/tắt từng channel
"""

from .notificationChannelInterface import NotificationChannel
from .telegramChannel import TelegramChannel
from .emailChannel import EmailChannel
from .notificationManager import NotificationManager

__all__ = ["NotificationChannel", "TelegramChannel", "EmailChannel", "NotificationManager"]
