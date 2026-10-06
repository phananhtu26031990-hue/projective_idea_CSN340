"""
Test Storage Layer
===================
Kiểm thử Logger, CSVFormatter, JSONFormatter, DatabaseFormatter.

Thiết kế test:
  - Dùng thư mục tạm (temp) để không ảnh hưởng đến file log thật
  - Cleanup sau mỗi test (xóa file tạm)
  - Kiểm tra nội dung file đã ghi
"""

import csv
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from models.alert import Alert
from storage.csvFormatter import CSVFormatter
from storage.jsonFormatter import JSONFormatter
from storage.databaseFormatter import DatabaseFormatter
from storage.logger import Logger


def makeTestAlert(id=1, severity="critical"):
    """Tạo Alert mẫu cho test."""
    return Alert(
        id=id,
        ruleName="TestRule",
        attackType="SYN Flood",
        sourceIp="192.168.1.100",
        destinationIp="10.0.0.1",
        severity=severity,
        confidence=0.95,
        timestamp=datetime(2026, 8, 19, 18, 0, 0),
        description="Test SYN Flood alert"
    )


class TestCSVFormatter(unittest.TestCase):

    def setUp(self):
        # Tạo thư mục tạm cho test
        self.temp_dir = tempfile.mkdtemp()
        self.csv_path = os.path.join(self.temp_dir, "test_alerts.csv")
        self.formatter = CSVFormatter(file_path=self.csv_path)
        self.formatter.setup()

    def tearDown(self):
        self.formatter.close()
        if os.path.exists(self.csv_path):
            os.remove(self.csv_path)
        os.rmdir(self.temp_dir)

    def test_file_created(self):
        """File CSV phải được tạo sau setup()."""
        self.assertTrue(os.path.exists(self.csv_path))

    def test_header_written(self):
        """Header phải được ghi khi file mới."""
        with open(self.csv_path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
        self.assertIn("id", first_line)
        self.assertIn("attackType", first_line)
        self.assertIn("severity", first_line)

    def test_write_alert(self):
        """Ghi alert phải tạo ra dòng CSV đúng."""
        alert = makeTestAlert(id=42)
        self.formatter.write(alert)
        self.formatter.close()

        with open(self.csv_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "42")
        self.assertEqual(rows[0]["attackType"], "SYN Flood")
        self.assertEqual(rows[0]["sourceIp"], "192.168.1.100")
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertEqual(rows[0]["confidence"], "0.95")

    def test_append_multiple_alerts(self):
        """Ghi nhiều alert phải append, không overwrite."""
        for i in range(1, 4):
            self.formatter.write(makeTestAlert(id=i))
        self.formatter.close()

        with open(self.csv_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 3)


class TestJSONFormatter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.json_path = os.path.join(self.temp_dir, "test_alerts.json")
        self.formatter = JSONFormatter(file_path=self.json_path)
        self.formatter.setup()

    def tearDown(self):
        self.formatter.close()
        if os.path.exists(self.json_path):
            os.remove(self.json_path)
        os.rmdir(self.temp_dir)

    def test_file_created(self):
        """File JSON phải được tạo sau setup()."""
        self.assertTrue(os.path.exists(self.json_path))

    def test_write_valid_json(self):
        """Mỗi dòng ghi phải là JSON hợp lệ (NDJSON format)."""
        alert = makeTestAlert(id=1)
        self.formatter.write(alert)
        self.formatter.close()

        with open(self.json_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["id"], 1)
        self.assertEqual(parsed["attackType"], "SYN Flood")
        self.assertEqual(parsed["confidence"], 0.95)

    def test_ndjson_format(self):
        """Nhiều alert → nhiều dòng JSON độc lập."""
        for i in range(3):
            self.formatter.write(makeTestAlert(id=i+1))
        self.formatter.close()

        with open(self.json_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        self.assertEqual(len(lines), 3)
        for i, line in enumerate(lines):
            parsed = json.loads(line)
            self.assertEqual(parsed["id"], i + 1)

    def test_read_all(self):
        """readAll() phải đọc lại đúng số alert đã ghi."""
        for i in range(5):
            self.formatter.write(makeTestAlert(id=i+1))
        self.formatter.close()

        alerts_read = self.formatter.readAll()
        self.assertEqual(len(alerts_read), 5)


class TestDatabaseFormatter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test.db")
        self.formatter = DatabaseFormatter(connection_string=self.db_path)
        self.formatter.setup()

    def tearDown(self):
        self.formatter.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.rmdir(self.temp_dir)

    def test_table_created(self):
        """Bảng alerts phải được tạo sau setup()."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        tables = cursor.fetchall()
        conn.close()
        self.assertEqual(len(tables), 1)

    def test_write_alert(self):
        """Ghi alert vào DB và đọc lại phải cho cùng dữ liệu."""
        alert = makeTestAlert(id=77)
        self.formatter.write(alert)

        results = self.formatter.query(
            "SELECT * FROM alerts WHERE id = ?", (77,)
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["attackType"], "SYN Flood")
        self.assertEqual(results[0]["sourceIp"], "192.168.1.100")
        self.assertAlmostEqual(results[0]["confidence"], 0.95)

    def test_query_by_severity(self):
        """Query theo severity phải hoạt động đúng."""
        self.formatter.write(makeTestAlert(id=1, severity="critical"))
        self.formatter.write(makeTestAlert(id=2, severity="high"))
        self.formatter.write(makeTestAlert(id=3, severity="critical"))

        critical = self.formatter.query(
            "SELECT * FROM alerts WHERE severity = ?", ("critical",)
        )
        self.assertEqual(len(critical), 2)

    def test_indexes_created(self):
        """Các index phải được tạo để tối ưu query."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        index_names = [row[0] for row in cursor.fetchall()]
        conn.close()

        self.assertIn("idx_severity", index_names)
        self.assertIn("idx_sourceIp", index_names)
        self.assertIn("idx_timestamp", index_names)


class TestLogger(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "formatters": {
                "csv": {"enabled": True, "path": os.path.join(self.temp_dir, "alerts.csv")},
                "json": {"enabled": True, "path": os.path.join(self.temp_dir, "alerts.json")},
                "database": {"enabled": False},
            }
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_logger_creates_all_formatters(self):
        """Logger phải khởi tạo đúng số formatter theo config."""
        log = Logger(config=self.config)
        # CSV + JSON được bật, Database tắt → 2 formatters
        self.assertEqual(len(log.formatters), 2)

    def test_log_alert_writes_to_all_formatters(self):
        """logAlert() phải ghi vào tất cả formatter đang bật."""
        log = Logger(config=self.config)
        log.setup()
        log.logAlert(makeTestAlert(id=1))
        log.close()

        # Kiểm tra file CSV
        csv_path = self.config["formatters"]["csv"]["path"]
        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 1)

        # Kiểm tra file JSON
        json_path = self.config["formatters"]["json"]["path"]
        with open(json_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(len(lines), 1)

    def test_context_manager(self):
        """Logger phải hỗ trợ context manager (with statement)."""
        csv_path = self.config["formatters"]["csv"]["path"]
        json_path = self.config["formatters"]["json"]["path"]

        with Logger(config=self.config) as log:
            log.logAlert(makeTestAlert(id=99))

        # File phải được tạo và đóng đúng cách
        self.assertTrue(os.path.exists(csv_path))
        self.assertTrue(os.path.exists(json_path))


if __name__ == "__main__":
    unittest.main()
