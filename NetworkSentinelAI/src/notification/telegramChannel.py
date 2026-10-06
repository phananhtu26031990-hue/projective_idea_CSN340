"""
TelegramChannel – Gửi cảnh báo qua Telegram Bot
=================================================
Telegram Bot API cho phép gửi tin nhắn đến cá nhân hoặc nhóm.

Cách tạo Telegram Bot:
  1. Tìm @BotFather trên Telegram
  2. Gửi /newbot, đặt tên, nhận token
  3. Lấy chat_id: gửi tin nhắn cho bot, gọi API getUpdates

Cấu hình (config.yaml):
  notifications:
    telegram:
      enabled: true
      token: "YOUR_BOT_TOKEN"
      chat_id: "YOUR_CHAT_ID"

API Telegram:
  POST https://api.telegram.org/bot{TOKEN}/sendMessage
  Body: {"chat_id": "...", "text": "...", "parse_mode": "HTML"}
"""

import json
import logging
import urllib.request
import urllib.error
import sys
import os
from typing import Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert
from notification.notificationChannelInterface import NotificationChannel

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


class TelegramChannel(NotificationChannel):
    """
    Gửi cảnh báo bảo mật qua Telegram Bot API.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Args:
            config (dict): {"enabled": bool, "token": str, "chat_id": str}
        """
        config = config or {}
        self._enabled = config.get("enabled", False)
        self._token = config.get("token", "")
        self._chat_id = config.get("chat_id", "")
        self._base_url = f"https://api.telegram.org/bot{self._token}/sendMessage"

    def isEnabled(self) -> bool:
        return self._enabled and bool(self._token) and bool(self._chat_id)

    def send(self, alert: Alert) -> bool:
        """
        Gửi tin nhắn Telegram với thông tin Alert.

        Format tin nhắn:
          🔴 [CRITICAL] SYN Flood Detected!
          ━━━━━━━━━━━━━━━━━━━━
          Source: 192.168.1.100
          Target: 10.0.0.1
          Confidence: 95.00%
          Rule: SynFloodDetection
          Time: 2026-08-19 18:30:00

        Args:
            alert (Alert): Alert cần gửi

        Returns:
            bool: True nếu gửi thành công
        """
        if not self.isEnabled():
            return False

        emoji = SEVERITY_EMOJI.get(alert.severity.lower(), "⚪")
        message = (
            f"{emoji} <b>[{alert.severity.upper()}] {alert.attackType} Detected!</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 <b>Source:</b> <code>{alert.sourceIp}</code>\n"
            f"🏹 <b>Target:</b> <code>{alert.destinationIp}</code>\n"
            f"📊 <b>Confidence:</b> {alert.confidence:.2%}\n"
            f"📋 <b>Rule:</b> {alert.ruleName}\n"
            f"🕐 <b>Time:</b> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"📝 <b>Details:</b> {alert.description[:200]}"
        )

        payload = {
            "chat_id": self._chat_id,
            "text": message,
            "parse_mode": "HTML"
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                self._base_url, data=data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))
                if result.get("ok"):
                    logger.debug(f"Telegram: Gửi alert #{alert.id} thành công")
                    return True
                else:
                    logger.warning(f"Telegram API lỗi: {result.get('description')}")
                    return False

        except urllib.error.URLError as e:
            logger.error(f"Telegram: Không thể kết nối: {e}")
            return False
        except Exception as e:
            logger.error(f"Telegram: Lỗi gửi alert #{alert.id}: {e}")
            return False
