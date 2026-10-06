"""
JSONFormatter – Ghi Alert ra file NDJSON
==========================================
NDJSON (Newline Delimited JSON): Mỗi dòng là 1 JSON object độc lập.
Khác với JSON array [], NDJSON cho phép append từng dòng mà không cần
parse toàn bộ file.

Ưu điểm NDJSON:
  - Append O(1): không cần đọc file cũ
  - Mỗi dòng có thể parse độc lập (streaming-friendly)
  - Tương thích với nhiều công cụ: jq, Elasticsearch, Splunk, Kibana
  - Dễ đọc bằng Python: json.loads(line) cho từng dòng

Ví dụ output:
  {"id": 1, "attackType": "SYN Flood", ...}
  {"id": 2, "attackType": "Port Scan", ...}
"""

import json
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert
from storage.logFormatterInterface import LogFormatter

logger = logging.getLogger(__name__)


class JSONFormatter(LogFormatter):
    """
    Ghi Alert vào file NDJSON (Newline Delimited JSON).
    Mỗi Alert chiếm một dòng JSON độc lập.
    """

    def __init__(self, file_path: str = "logs/alerts.json"):
        """
        Args:
            file_path (str): Đường dẫn file JSON output
        """
        self.file_path = file_path
        self._file = None

    def setup(self) -> None:
        """
        Tạo thư mục nếu chưa có và mở file ở chế độ append.
        """
        os.makedirs(os.path.dirname(self.file_path) or ".", exist_ok=True)
        self._file = open(self.file_path, "a", encoding="utf-8")
        logger.info(f"JSONFormatter sẵn sàng: {self.file_path}")

    def write(self, alert: Alert) -> None:
        """
        Ghi một dòng JSON cho Alert (NDJSON format).

        Args:
            alert (Alert): Alert cần ghi
        """
        if not self._file:
            logger.warning("JSONFormatter chưa được setup(). Bỏ qua ghi log.")
            return

        try:
            json_line = json.dumps(alert.toDictionary(), ensure_ascii=False)
            self._file.write(json_line + "\n")
            self._file.flush()      # Flush ngay để đảm bảo data không mất
        except Exception as e:
            logger.error(f"JSONFormatter: Lỗi ghi alert #{alert.id}: {e}")

    def close(self) -> None:
        """Đóng file JSON."""
        if self._file:
            try:
                self._file.flush()
                self._file.close()
                self._file = None
                logger.info("JSONFormatter: Đã đóng file")
            except Exception as e:
                logger.error(f"JSONFormatter: Lỗi đóng file: {e}")

    def readAll(self) -> list:
        """
        Đọc toàn bộ alert đã ghi trong file (tiện ích phân tích sau).

        Returns:
            list: Danh sách dict của các alert
        """
        alerts = []
        if not os.path.exists(self.file_path):
            return alerts
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        alerts.append(json.loads(line))
        except Exception as e:
            logger.error(f"JSONFormatter: Lỗi đọc file: {e}")
        return alerts
