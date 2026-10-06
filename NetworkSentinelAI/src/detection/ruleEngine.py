"""
RuleEngine – Bộ máy phân tích rule
=====================================
Điều phối việc chạy tất cả các detection rule trên một Traffic window.

Thiết kế:
  - RuleEngine giữ danh sách các Rule objects
  - Khi analyze() được gọi, nó chạy TẤT CẢ rules trên traffic
  - Tổng hợp kết quả (Alert list) từ tất cả rules
  - Nếu 1 rule bị lỗi, các rule khác vẫn tiếp tục chạy (fault tolerance)

Luồng xử lý:
  Traffic window (đã đóng)
      ↓
  RuleEngine.analyze(traffic)
      ↓
  [SynFloodRule, AckFloodRule, PortScanRule, ICMPTunnelRule] → chạy song song
      ↓
  List[Alert] (tổng hợp từ tất cả rules)
"""

import logging
import sys
import os
from typing import List, Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.traffic import Traffic
from models.alert import Alert
from detection.ruleInterface import Rule
from detection.rules.syn_flood.synFloodRule import SynFloodRule
from detection.rules.ack_flood.ackFloodRule import AckFloodRule
from detection.rules.port_scan.portScanRule import PortScanRule
from detection.rules.icmp_tunnel.icmpTunnelRule import ICMPTunnelRule

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Bộ máy phát hiện tấn công dựa trên rule-based.

    Attributes:
        rules (List[Rule]): Danh sách các rule đang hoạt động
        alertCounter (int): Bộ đếm ID cho Alert (tự tăng)
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Khởi tạo RuleEngine với các rule mặc định.

        Args:
            config (dict): Cấu hình ngưỡng từ config.yaml
                           Ví dụ: {"syn_flood": {"threshold": 100.0}, ...}
        """
        config = config or {}
        rules_config = config.get("rules", {})

        self.alertCounter: int = 0

        # Khởi tạo tất cả rules với ngưỡng từ config
        self.rules: List[Rule] = [
            SynFloodRule(threshold=rules_config.get("syn_flood", {}).get("threshold", 100.0)),
            AckFloodRule(threshold=rules_config.get("ack_flood", {}).get("threshold", 150.0)),
            PortScanRule(threshold=rules_config.get("port_scan", {}).get("threshold", 50.0)),
            ICMPTunnelRule(threshold=rules_config.get("icmp_tunnel", {}).get("threshold", 30.0)),
        ]

        logger.info(f"RuleEngine khởi tạo với {len(self.rules)} rules: "
                    f"{[r.ruleName for r in self.rules]}")

    def analyze(self, traffic: Traffic) -> List[Alert]:
        """
        Chạy tất cả rules trên một Traffic window và trả về danh sách Alert.

        Thiết kế fault-tolerant:
          - Mỗi rule được wrap trong try/except riêng
          - Nếu 1 rule crash → log lỗi, tiếp tục với rule tiếp theo
          - Đảm bảo hệ thống không chết vì một rule bị bug

        Args:
            traffic (Traffic): Cửa sổ traffic cần phân tích

        Returns:
            List[Alert]: Tất cả alert từ tất cả rules (có thể rỗng)
        """
        if not traffic or traffic.totalPackets == 0:
            return []

        all_alerts: List[Alert] = []

        for rule in self.rules:
            try:
                alerts = rule.analyze(traffic)

                # Gán ID tăng dần cho mỗi alert
                for alert in alerts:
                    self.alertCounter += 1
                    alert.id = self.alertCounter

                all_alerts.extend(alerts)

                if alerts:
                    logger.warning(
                        f"[{rule.ruleName}] Phát hiện {len(alerts)} alert(s) "
                        f"trong window {traffic.startTime} → {traffic.endTime}"
                    )

            except Exception as e:
                # Rule bị lỗi không làm sập cả hệ thống
                logger.error(f"Rule '{rule.ruleName}' bị lỗi: {e}", exc_info=True)
                continue

        if all_alerts:
            logger.info(f"RuleEngine: Tổng cộng {len(all_alerts)} alert(s) trong window này")

        return all_alerts

    def addRule(self, rule: Rule) -> None:
        """
        Thêm một rule mới vào engine (hỗ trợ mở rộng dynamic).

        Args:
            rule (Rule): Rule object cần thêm
        """
        self.rules.append(rule)
        logger.info(f"Thêm rule mới: {rule.ruleName}")

    def removeRule(self, rule_name: str) -> bool:
        """
        Xóa rule theo tên.

        Args:
            rule_name (str): Tên rule cần xóa

        Returns:
            bool: True nếu xóa thành công, False nếu không tìm thấy
        """
        original_count = len(self.rules)
        self.rules = [r for r in self.rules if r.ruleName != rule_name]
        removed = len(self.rules) < original_count
        if removed:
            logger.info(f"Đã xóa rule: {rule_name}")
        return removed
