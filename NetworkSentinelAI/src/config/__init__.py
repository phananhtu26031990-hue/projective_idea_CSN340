"""
Layer 9 – Config Layer
========================
Đọc và quản lý cấu hình từ file config.yaml.

ConfigLoader cung cấp:
  - Đọc file YAML một lần duy nhất khi khởi động
  - Getter methods cho từng phần cấu hình
  - Giá trị mặc định nếu key không tồn tại
  - Singleton pattern: mọi nơi dùng chung 1 instance config
"""

from .configLoader import ConfigLoader

__all__ = ["ConfigLoader"]
