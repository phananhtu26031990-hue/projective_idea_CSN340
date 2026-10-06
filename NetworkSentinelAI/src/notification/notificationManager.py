"""
NotificationManager – Điều phối thông báo
==========================================
Quản lý và điều phối việc gửi cảnh báo qua tất cả channel đang bật.

Thiết kế:
  - Chỉ gửi alert có severity >= min_severity (lọc spam)
  - Fault-tolerant: 1 channel lỗi → channel khác vẫn gửi
  - Có thể gọi thủ công hoặc gọi tự động từ AlertManager
"""

import logging
import sys
import os
from typing import List, Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert
from notification.notificationChannelInterface import NotificationChannel
from notification.telegramChannel import TelegramChannel
from notification.emailChannel import EmailChannel

logger = logging.getLogger(__name__)

# Thứ tự ưu tiên severity: thấp = ưu tiên cao
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class NotificationManager:
    """
    Điều phối việc gửi thông báo qua tất cả kênh đang hoạt động.
    """

    def __init__(self, config: Dict[str, Any] = None, min_severity: str = "high"):
        """
        Args:
            config (dict): Config từ config.yaml, phần "notifications"
            min_severity (str): Mức severity tối thiểu để gửi thông báo.
                                "high" = chỉ gửi khi severity là high hoặc critical.
        """
        config = config or {}
        self.min_severity = min_severity
        self._channels: List[NotificationChannel] = []

        # Khởi tạo Telegram channel
        telegram_config = config.get("telegram", {})
        telegram = TelegramChannel(config=telegram_config)
        if telegram.isEnabled():
            self._channels.append(telegram)
            logger.info("NotificationManager: Telegram channel đã bật")

        # Khởi tạo Email channel
        email_config = config.get("email", {})
        email = EmailChannel(config=email_config)
        if email.isEnabled():
            self._channels.append(email)
            logger.info("NotificationManager: Email channel đã bật")

        if not self._channels:
            logger.info("NotificationManager: Không có channel nào được bật (cấu hình trong config.yaml)")

    def notify(self, alert: Alert) -> int:
        """
        Gửi thông báo alert qua tất cả channel đang bật (nếu severity đủ cao).

        Args:
            alert (Alert): Alert cần thông báo

        Returns:
            int: Số channel gửi thành công
        """
        if not self._channels:
            return 0

        # Kiểm tra mức severity
        alert_priority = SEVERITY_ORDER.get(alert.severity.lower(), 99)
        min_priority = SEVERITY_ORDER.get(self.min_severity.lower(), 1)

        if alert_priority > min_priority:      # Số thấp = priority cao → bỏ qua nếu > min
            logger.debug(f"NotificationManager: Alert #{alert.id} severity '{alert.severity}' "
                         f"< min_severity '{self.min_severity}' → bỏ qua")
            return 0

        success_count = 0
        for channel in self._channels:
            try:
                if channel.send(alert):
                    success_count += 1
            except Exception as e:
                logger.error(f"Lỗi gửi qua {type(channel).__name__}: {e}")

        return success_count

    def notifyBatch(self, alerts: List[Alert]) -> int:
        """
        Gửi thông báo cho nhiều Alert, chỉ gửi alert critical (tránh spam).

        Với batch, chúng ta thường chỉ gửi tóm tắt hoặc chỉ critical alerts.

        Args:
            alerts (List[Alert]): Danh sách Alert

        Returns:
            int: Tổng số lần gửi thành công
        """
        total = 0
        # Chỉ gửi critical alerts trong batch mode để tránh spam
        critical_alerts = [a for a in alerts if a.severity.lower() == "critical"]
        for alert in critical_alerts:
            total += self.notify(alert)
        return total
