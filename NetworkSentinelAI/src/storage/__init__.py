"""
Layer 5 – Storage Layer
========================
Ghi và lưu trữ alert như bằng chứng bảo mật.

Kiến trúc Strategy Pattern:
  Logger ──── LogFormatter (Interface/ABC)
                  │
                  ├── CSVFormatter    → file .csv
                  ├── JSONFormatter   → file .json (NDJSON)
                  └── DatabaseFormatter → SQLite

Tại sao dùng Strategy Pattern?
  - Dễ thêm format mới (ElasticSearch, Splunk...) mà không sửa Logger
  - Logger không quan tâm định dạng output, chỉ gọi formatter.write()
  - Cấu hình từ config.yaml: bật/tắt từng formatter độc lập

QUAN TRỌNG (từ comment trong task.txt):
  "Log là bằng chứng, AI chỉ là công cụ hỗ trợ"
  Logger phải được gọi TRƯỚC, KHÔNG ĐỢI AI. Chạy song song.
"""

from .logFormatterInterface import LogFormatter
from .csvFormatter import CSVFormatter
from .jsonFormatter import JSONFormatter
from .databaseFormatter import DatabaseFormatter
from .logger import Logger

__all__ = ["LogFormatter", "CSVFormatter", "JSONFormatter", "DatabaseFormatter", "Logger"]
