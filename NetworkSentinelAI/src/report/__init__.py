"""
Layer 7 – Report Layer
========================
Tổng hợp toàn bộ thông tin bảo mật thành báo cáo có thể đọc và lưu trữ.

Luồng:
  AlertManager + AIResult + Statistics
              ↓
      ReportGenerator.generate()
              ↓
           Report
              ↓
      ReportExporter.export()
              ↓
    [PDF] [TXT] [HTML]
"""

from .reportGenerator import ReportGenerator
from .reportExporter import ReportExporter

__all__ = ["ReportGenerator", "ReportExporter"]
