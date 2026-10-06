"""
ConfigLoader – Đọc cấu hình từ YAML
======================================
Singleton-like loader đọc file config.yaml và cung cấp
các getter method thuận tiện cho từng phần cấu hình.

Tại sao dùng config file thay vì hard-code?
  - Dễ thay đổi threshold mà không cần sửa code
  - Dễ tùy chỉnh cho từng môi trường (dev/prod)
  - Non-developer cũng có thể điều chỉnh cấu hình

Cấu trúc config.yaml:
  capture: { interface, filter }
  traffic: { window_size }
  rules: { syn_flood: { threshold }, ack_flood: {...}, ... }
  security_analyzer: { model, threshold }
  logging: { formatters: { csv: {...}, json: {...}, database: {...} } }
  notifications: { telegram: {...}, email: {...} }
"""

import logging
import os
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Đường dẫn mặc định đến config.yaml
DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "config.yaml"
)


class ConfigLoader:
    """
    Đọc và cung cấp cấu hình từ file YAML.

    Attributes:
        _config (Dict): Dictionary chứa toàn bộ cấu hình đã parse
        config_path (str): Đường dẫn file config đang dùng
    """

    def __init__(self, config_path: str = None):
        """
        Args:
            config_path (str): Đường dẫn đến config.yaml.
                               Mặc định: config/config.yaml trong thư mục project.
        """
        self.config_path = config_path or os.path.abspath(DEFAULT_CONFIG_PATH)
        self._config: Dict = {}
        self._load()

    def _load(self) -> None:
        """
        Đọc và parse file YAML. Được gọi tự động khi khởi tạo.
        Nếu file không tồn tại hoặc lỗi → dùng dict rỗng, log warning.
        """
        try:
            import yaml
            with open(self.config_path, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f) or {}
            logger.info(f"Đã load config từ: {self.config_path}")
        except FileNotFoundError:
            logger.warning(f"Config file không tìm thấy: {self.config_path}. Dùng giá trị mặc định.")
            self._config = {}
        except Exception as e:
            logger.error(f"Lỗi đọc config: {e}. Dùng giá trị mặc định.")
            self._config = {}

    def get(self, *keys: str, default: Any = None) -> Any:
        """
        Lấy giá trị config theo đường dẫn key lồng nhau.

        Args:
            *keys: Chuỗi key lồng nhau. Ví dụ: get("rules", "syn_flood", "threshold")
            default: Giá trị mặc định nếu key không tồn tại

        Returns:
            Any: Giá trị config hoặc default

        Ví dụ:
            loader.get("traffic", "window_size", default=10)
            loader.get("rules", "syn_flood", "threshold", default=100.0)
        """
        current = self._config
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return default
            current = current[key]
        return current

    # ── Getter shortcuts cho từng section ─────────────────────────────────

    def getCaptureConfig(self) -> Dict:
        """Lấy cấu hình capture (interface, filter)."""
        return self._config.get("capture", {"interface": "eth0", "filter": "ip"})

    def getTrafficConfig(self) -> Dict:
        """Lấy cấu hình traffic window."""
        return self._config.get("traffic", {"window_size": 10})

    def getRulesConfig(self) -> Dict:
        """Lấy cấu hình ngưỡng cho tất cả detection rules."""
        return self._config.get("rules", {})

    def getAIConfig(self) -> Dict:
        """Lấy cấu hình AI Security Analyzer."""
        return self._config.get("security_analyzer", {"model": "llama2", "threshold": 0.85})

    def getLoggingConfig(self) -> Dict:
        """Lấy cấu hình Storage/Logging."""
        return self._config.get("logging", {})

    def getNotificationConfig(self) -> Dict:
        """Lấy cấu hình Notification channels."""
        return self._config.get("notifications", {})

    def getWindowSize(self) -> int:
        """Lấy kích thước cửa sổ traffic (giây)."""
        return int(self.get("traffic", "window_size", default=10))

    def getInterface(self) -> str:
        """Lấy tên card mạng cần monitor."""
        return str(self.get("capture", "interface", default="eth0"))

    def getBpfFilter(self) -> str:
        """Lấy BPF filter."""
        return str(self.get("capture", "filter", default="ip"))

    def getAll(self) -> Dict:
        """Trả về toàn bộ config dict (dùng cho debug)."""
        return dict(self._config)

    def reload(self) -> None:
        """Load lại config từ file (hữu ích khi file được chỉnh sửa khi đang chạy)."""
        self._load()
        logger.info("Config đã được reload")
