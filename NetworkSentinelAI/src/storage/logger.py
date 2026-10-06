"""
Logger – Điều phối ghi log
============================
Logger là lớp trung tâm của Storage Layer. Nó nhận Alert và
phân phát đến tất cả formatter đang được bật.

Thiết kế quan trọng (từ task.txt):
  "Log là bằng chứng, AI chỉ là công cụ hỗ trợ"
  → Logger PHẢI được gọi TRƯỚC khi đợi AI
  → Nếu AI lỗi/chậm, log vẫn phải đã được ghi
  → Trong main.py: logAlert() được gọi NGAY sau khi có Alert,
    AI analysis chạy song song (concurrent.futures / threading)

Ví dụ thiết kế song song trong pipeline:
  [Alert created]
       ↓
  ┌────┴──────┐
  │          │
  Logger    SecurityAnalyzer  ← chạy đồng thời (threading)
  (ghi ngay)  (có thể chậm)
  │          │
  └────┬──────┘
       ↓
  [Tiếp tục pipeline...]
"""

import logging
import sys
import os
from typing import List, Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert
from storage.logFormatterInterface import LogFormatter
from storage.csvFormatter import CSVFormatter
from storage.jsonFormatter import JSONFormatter
from storage.databaseFormatter import DatabaseFormatter

logger = logging.getLogger(__name__)


class Logger:
    """
    Điều phối ghi log Alert qua nhiều formatter cùng lúc.

    Attributes:
        formatters (List[LogFormatter]): Danh sách formatter đang hoạt động
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Khởi tạo Logger và tất cả formatter được bật trong config.

        Args:
            config (dict): Config từ config.yaml, phần "logging"
                           Ví dụ:
                           {
                             "formatters": {
                               "csv": {"enabled": true, "path": "logs/alerts.csv"},
                               "json": {"enabled": true, "path": "logs/alerts.json"},
                               "database": {"enabled": false, ...}
                             }
                           }
        """
        config = config or {}
        formatters_config = config.get("formatters", {})

        self.formatters: List[LogFormatter] = []

        # ── CSV Formatter ──────────────────────────────────────────────────
        csv_config = formatters_config.get("csv", {})
        if csv_config.get("enabled", True):
            csv_path = csv_config.get("path", "logs/alerts.csv")
            self.formatters.append(CSVFormatter(file_path=csv_path))

        # ── JSON Formatter ─────────────────────────────────────────────────
        json_config = formatters_config.get("json", {})
        if json_config.get("enabled", True):
            json_path = json_config.get("path", "logs/alerts.json")
            self.formatters.append(JSONFormatter(file_path=json_path))

        # ── Database Formatter ─────────────────────────────────────────────
        db_config = formatters_config.get("database", {})
        if db_config.get("enabled", False):
            conn_str = db_config.get("connection_string", "logs/sentinel.db")
            self.formatters.append(DatabaseFormatter(connection_string=conn_str))

        logger.info(f"Logger khởi tạo với {len(self.formatters)} formatter(s): "
                    f"{[type(f).__name__ for f in self.formatters]}")

    def setup(self) -> None:
        """
        Khởi tạo tất cả formatter (tạo file, bảng DB...).
        Phải gọi trước khi dùng logAlert().
        """
        for formatter in self.formatters:
            try:
                formatter.setup()
            except Exception as e:
                logger.error(f"Lỗi setup {type(formatter).__name__}: {e}")

    def logAlert(self, alert: Alert) -> None:
        """
        Ghi một Alert qua tất cả formatter đang bật.

        QUAN TRỌNG: Phương thức này được thiết kế để gọi NGAY LẬP TỨC
        khi có alert, KHÔNG đợi AI analysis hoàn tất.

        Nếu một formatter lỗi, các formatter khác vẫn tiếp tục.
        (Fault tolerance: lỗi CSV không ảnh hưởng JSON)

        Args:
            alert (Alert): Alert cần ghi
        """
        for formatter in self.formatters:
            try:
                formatter.write(alert)
            except Exception as e:
                logger.error(f"Lỗi ghi log bằng {type(formatter).__name__}: {e}")

    def logAlerts(self, alerts: List[Alert]) -> None:
        """
        Ghi nhiều Alert cùng lúc.

        Args:
            alerts (List[Alert]): Danh sách Alert cần ghi
        """
        for alert in alerts:
            self.logAlert(alert)

    def close(self) -> None:
        """
        Đóng tất cả formatter khi hệ thống tắt.
        Đảm bảo không mất data còn trong buffer.
        """
        for formatter in self.formatters:
            try:
                formatter.close()
            except Exception as e:
                logger.error(f"Lỗi đóng {type(formatter).__name__}: {e}")
        logger.info("Logger: Đã đóng tất cả formatter")

    def __enter__(self):
        """Hỗ trợ context manager: with Logger() as log:"""
        self.setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Tự động close() khi ra khỏi context manager."""
        self.close()
