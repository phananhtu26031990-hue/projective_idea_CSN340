"""
Helpers – Hàm tiện ích dùng chung
=====================================
Các hàm utility nhỏ, không thuộc về layer cụ thể nào.
Được dùng bởi nhiều module khác nhau trong hệ thống.
"""

import logging
import logging.handlers
import os
import uuid
from datetime import datetime


def formatBytes(bytes_count: int, precision: int = 2) -> str:
    """
    Chuyển đổi số bytes thành chuỗi dễ đọc.

    Args:
        bytes_count (int): Số bytes
        precision (int): Số chữ số thập phân

    Returns:
        str: Ví dụ "1.50 MB", "256.00 KB", "1.20 GB"

    Ví dụ:
        formatBytes(1500000)    → "1.43 MB"
        formatBytes(256)        → "256 B"
        formatBytes(1073741824) → "1.00 GB"
    """
    if bytes_count < 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(bytes_count)

    for unit in units[:-1]:
        if size < 1024.0:
            return f"{size:.{precision}f} {unit}"
        size /= 1024.0

    return f"{size:.{precision}f} {units[-1]}"


def formatDuration(seconds: float) -> str:
    """
    Chuyển đổi số giây thành chuỗi thời gian dễ đọc.

    Args:
        seconds (float): Số giây

    Returns:
        str: Ví dụ "2m 30s", "1h 5m 10s", "45.3s"

    Ví dụ:
        formatDuration(90)    → "1m 30s"
        formatDuration(3670)  → "1h 1m 10s"
        formatDuration(5.3)   → "5.3s"
    """
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    remaining_seconds = int(seconds % 60)

    if minutes < 60:
        return f"{minutes}m {remaining_seconds}s"

    hours = int(minutes // 60)
    remaining_minutes = minutes % 60
    return f"{hours}h {remaining_minutes}m {remaining_seconds}s"


def formatTimestamp(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Định dạng datetime thành chuỗi.

    Args:
        dt (datetime): Đối tượng datetime
        format_str (str): Format string

    Returns:
        str: Chuỗi thời gian định dạng
    """
    if dt is None:
        return "N/A"
    return dt.strftime(format_str)


def generateReportId(prefix: str = "rpt") -> str:
    """
    Tạo ID duy nhất cho báo cáo theo format: prefix-YYYYMMDD-HHMMSS-XXXXXX.

    Args:
        prefix (str): Tiền tố của ID

    Returns:
        str: ID duy nhất, ví dụ "rpt-20260819-183000-A1B2C3"

    Thiết kế:
        - Chứa timestamp để dễ tìm kiếm theo ngày
        - Chứa UUID ngắn để tránh collision khi nhiều báo cáo cùng giây
    """
    now = datetime.now()
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"{prefix}-{now.strftime('%Y%m%d-%H%M%S')}-{short_uuid}"


def truncateText(text: str, max_length: int = 200, suffix: str = "...") -> str:
    """
    Cắt ngắn chuỗi text nếu dài hơn max_length.

    Args:
        text (str): Chuỗi cần cắt
        max_length (int): Độ dài tối đa (không tính suffix)
        suffix (str): Chuỗi thêm vào cuối nếu bị cắt

    Returns:
        str: Chuỗi đã cắt ngắn (hoặc nguyên vẹn nếu đủ ngắn)
    """
    if not text or len(text) <= max_length:
        return text
    return text[:max_length] + suffix


def setupLogging(
    log_level: str = "INFO",
    log_file: str = "logs/sentinel.log",
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5
) -> None:
    """
    Cấu hình hệ thống logging Python cho toàn bộ ứng dụng.

    Thiết lập:
      - Console handler: In ra màn hình với màu sắc (level INFO+)
      - File handler: Ghi vào file với rotation tự động (level DEBUG+)
      - Format thống nhất với timestamp, module name, level

    Args:
        log_level (str): Mức log ("DEBUG", "INFO", "WARNING", "ERROR")
        log_file (str): Đường dẫn file log
        max_bytes (int): Kích thước tối đa file log trước khi rotate
        backup_count (int): Số file backup giữ lại sau rotate

    Cách dùng:
        # Gọi 1 lần ở đầu main.py
        setupLogging(log_level="INFO", log_file="logs/sentinel.log")

        # Sau đó ở các module khác:
        logger = logging.getLogger(__name__)
        logger.info("Thông tin")
    """
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)

    # Format log: [2026-08-19 18:30:00] [INFO] module_name: Message
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Console handler
    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    # Rotating file handler
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root_logger.handlers):
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    logging.getLogger(__name__).info(
        f"Logging đã cấu hình: level={log_level}, file={log_file}"
    )
