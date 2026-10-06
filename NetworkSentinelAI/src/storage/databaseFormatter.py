"""
DatabaseFormatter – Ghi Alert vào SQLite Database
===================================================
SQLite là database nhúng (embedded), không cần server riêng.
Phù hợp cho IDS cỡ vừa, dễ truy vấn bằng SQL.

Cấu trúc bảng alerts:
  CREATE TABLE alerts (
      id          INTEGER PRIMARY KEY,
      ruleName    TEXT,
      attackType  TEXT,
      sourceIp    TEXT,
      destinationIp TEXT,
      severity    TEXT,
      confidence  REAL,
      timestamp   TEXT,   -- ISO format
      description TEXT,
      createdAt   TEXT    -- Thời gian ghi vào DB
  );

Ưu điểm SQLite:
  - Truy vấn SQL: SELECT * FROM alerts WHERE severity='critical'
  - Index: tìm kiếm nhanh theo IP, severity, time range
  - Transactions: đảm bảo tính toàn vẹn khi ghi
"""

import sqlite3
import logging
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert
from storage.logFormatterInterface import LogFormatter

logger = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER,
    ruleName        TEXT NOT NULL,
    attackType      TEXT NOT NULL,
    sourceIp        TEXT NOT NULL,
    destinationIp   TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    timestamp       TEXT NOT NULL,
    description     TEXT,
    createdAt       TEXT NOT NULL
);
"""

CREATE_INDEX_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_severity ON alerts (severity);",
    "CREATE INDEX IF NOT EXISTS idx_sourceIp ON alerts (sourceIp);",
    "CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts (timestamp);",
]

INSERT_SQL = """
INSERT INTO alerts (id, ruleName, attackType, sourceIp, destinationIp,
                   severity, confidence, timestamp, description, createdAt)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""


class DatabaseFormatter(LogFormatter):
    """
    Ghi Alert vào SQLite database.
    Hỗ trợ query SQL sau này để phân tích lịch sử alert.
    """

    def __init__(self, connection_string: str = "logs/sentinel.db"):
        """
        Args:
            connection_string (str): Đường dẫn file SQLite DB
        """
        self.db_path = connection_string.replace("sqlite:///", "")
        self._conn: sqlite3.Connection = None

    def setup(self) -> None:
        """
        Tạo file DB, bảng, và index nếu chưa tồn tại.
        """
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        try:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.execute(CREATE_TABLE_SQL)
            for idx_sql in CREATE_INDEX_SQL:
                self._conn.execute(idx_sql)
            self._conn.commit()
            logger.info(f"DatabaseFormatter sẵn sàng: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"DatabaseFormatter: Lỗi khởi tạo DB: {e}")
            raise

    def write(self, alert: Alert) -> None:
        """
        Ghi một Alert vào bảng alerts.

        Args:
            alert (Alert): Alert cần ghi
        """
        if not self._conn:
            logger.warning("DatabaseFormatter chưa được setup(). Bỏ qua.")
            return

        try:
            alert_dict = alert.toDictionary()
            self._conn.execute(INSERT_SQL, (
                alert_dict["id"],
                alert_dict["ruleName"],
                alert_dict["attackType"],
                alert_dict["sourceIp"],
                alert_dict["destinationIp"],
                alert_dict["severity"],
                alert_dict["confidence"],
                alert_dict["timestamp"],
                alert_dict["description"],
                datetime.now().isoformat(),     # Thời gian ghi vào DB (khác với thời gian phát hiện)
            ))
            self._conn.commit()
        except sqlite3.Error as e:
            logger.error(f"DatabaseFormatter: Lỗi ghi alert #{alert.id}: {e}")

    def query(self, sql: str, params: tuple = ()) -> list:
        """
        Thực thi câu lệnh SQL tùy ý để truy vấn alert lịch sử.

        Args:
            sql (str): Câu lệnh SQL SELECT
            params (tuple): Parameters (tránh SQL injection)

        Returns:
            list: Danh sách dict kết quả

        Ví dụ:
            db.query("SELECT * FROM alerts WHERE severity=?", ("critical",))
        """
        if not self._conn:
            return []
        try:
            cursor = self._conn.execute(sql, params)
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"DatabaseFormatter: Lỗi query: {e}")
            return []

    def close(self) -> None:
        """Đóng kết nối DB."""
        if self._conn:
            try:
                self._conn.close()
                self._conn = None
                logger.info("DatabaseFormatter: Đã đóng kết nối DB")
            except Exception as e:
                logger.error(f"DatabaseFormatter: Lỗi đóng DB: {e}")
