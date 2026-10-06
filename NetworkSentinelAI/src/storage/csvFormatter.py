"""
CSVFormatter – Ghi Alert ra file CSV
======================================
CSV (Comma-Separated Values) là định dạng dễ đọc bằng Excel, pandas, spreadsheet.

Cấu trúc file CSV:
  id, ruleName, attackType, sourceIp, destinationIp, severity, confidence, timestamp, description

Thiết kế:
  - Tạo header khi file chưa tồn tại
  - Append từng dòng (không overwrite)
  - Thread-safe: mỗi write() flush ngay để đảm bảo không mất data nếu crash
"""

import csv
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert
from storage.logFormatterInterface import LogFormatter

logger = logging.getLogger(__name__)

# Các cột trong CSV
CSV_FIELDS = ["id", "ruleName", "attackType", "sourceIp", "destinationIp",
              "severity", "confidence", "timestamp", "description"]


class CSVFormatter(LogFormatter):
    """
    Ghi Alert vào file CSV với header tự động.
    """

    def __init__(self, file_path: str = "logs/alerts.csv"):
        """
        Args:
            file_path (str): Đường dẫn file CSV output
        """
        self.file_path = file_path
        self._file = None
        self._writer = None

    def setup(self) -> None:
        """
        Tạo thư mục nếu chưa có, mở file CSV.
        Ghi header nếu file mới (chưa tồn tại hoặc rỗng).
        """
        os.makedirs(os.path.dirname(self.file_path) or ".", exist_ok=True)

        # Kiểm tra file có tồn tại và có nội dung không
        file_exists = os.path.exists(self.file_path) and os.path.getsize(self.file_path) > 0

        # Mở file ở chế độ append
        self._file = open(self.file_path, "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=CSV_FIELDS)

        # Chỉ ghi header nếu file mới
        if not file_exists:
            self._writer.writeheader()
            self._file.flush()

        logger.info(f"CSVFormatter sẵn sàng: {self.file_path}")

    def write(self, alert: Alert) -> None:
        """
        Ghi một dòng CSV cho Alert.
        Flush ngay sau khi ghi để đảm bảo data không bị mất nếu crash.

        Args:
            alert (Alert): Alert cần ghi
        """
        if not self._writer:
            logger.warning("CSVFormatter chưa được setup(). Bỏ qua ghi log.")
            return

        try:
            alert_dict = alert.toDictionary()
            row = {field: alert_dict.get(field, "") for field in CSV_FIELDS}
            self._writer.writerow(row)
            self._file.flush()      # Flush ngay: quan trọng cho tính pháp lý của log
        except Exception as e:
            logger.error(f"CSVFormatter: Lỗi ghi alert #{alert.id}: {e}")

    def close(self) -> None:
        """Đóng file CSV."""
        if self._file:
            try:
                self._file.flush()
                self._file.close()
                self._file = None
                self._writer = None
                logger.info("CSVFormatter: Đã đóng file")
            except Exception as e:
                logger.error(f"CSVFormatter: Lỗi đóng file: {e}")
