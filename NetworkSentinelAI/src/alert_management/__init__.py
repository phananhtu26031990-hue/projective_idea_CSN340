"""
Layer 4 – Alert Management Layer
==================================
Quản lý vòng đời của các Alert trong hệ thống IDS.

AlertManager là trung tâm lưu trữ và tra cứu alert:
  - Nhận alert từ RuleEngine
  - Lưu vào danh sách nội bộ
  - Cung cấp các phương thức lọc, tìm kiếm, thống kê

Cách dùng:
    manager = AlertManager()
    manager.addAlert(alert)
    critical_alerts = manager.filterBySeverity("critical")
"""

from .alertManager import AlertManager

__all__ = ["AlertManager"]
