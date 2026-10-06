"""
Rule Interface (Abstract Base Class)
======================================
Định nghĩa giao diện chung cho tất cả các rule phát hiện tấn công.

Tại sao dùng ABC (Abstract Base Class)?
  - Đảm bảo mọi rule đều implement method analyze()
  - RuleEngine chỉ cần biết về interface Rule, không cần biết chi tiết từng rule
  - Dễ thêm rule mới mà không cần sửa RuleEngine (Open/Closed Principle)

Ví dụ tạo rule mới:
    class MyCustomRule(Rule):
        def analyze(self, traffic: Traffic) -> List[Alert]:
            # Logic phát hiện tùy chỉnh
            return [Alert(...)]
"""

import sys
import os
from abc import ABC, abstractmethod
from typing import List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.traffic import Traffic
from models.alert import Alert


class Rule(ABC):
    """
    Interface (ABC) cho tất cả các Detection Rule.

    Mỗi rule con phải implement phương thức analyze() để phân tích
    một Traffic window và trả về danh sách các Alert được phát hiện.
    """

    @property
    @abstractmethod
    def ruleName(self) -> str:
        """Tên của rule (dùng để nhận diện trong Alert và log)."""
        pass

    @abstractmethod
    def analyze(self, traffic: Traffic) -> List[Alert]:
        """
        Phân tích một Traffic window và phát hiện các cuộc tấn công.

        Args:
            traffic (Traffic): Cửa sổ traffic cần phân tích

        Returns:
            List[Alert]: Danh sách alert được tạo ra (rỗng nếu không phát hiện)
        """
        pass
