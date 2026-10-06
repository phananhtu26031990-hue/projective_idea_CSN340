"""
Layer 3 – Detection Layer
==========================
Phát hiện các kiểu tấn công mạng thông qua hệ thống rule-based.

Kiến trúc:
  RuleEngine ──── Rule (Interface/ABC)
                      │
                      ├── SynFloodRule
                      ├── AckFloodRule
                      ├── PortScanRule
                      └── ICMPTunnelRule

Cách dùng:
    engine = RuleEngine(config)
    alerts = engine.analyze(traffic)
"""

from .ruleInterface import Rule
from .ruleEngine import RuleEngine

__all__ = ["Rule", "RuleEngine"]
