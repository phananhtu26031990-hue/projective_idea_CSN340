"""
ReportGenerator – Tạo báo cáo bảo mật
========================================
Tổng hợp dữ liệu từ nhiều nguồn (Alert, AIResult, Traffic Statistics)
thành một Report object có cấu trúc.

Vai trò:
  - Không tự thu thập dữ liệu (đó là việc của AlertManager, SecurityAnalyzer)
  - Chỉ nhận dữ liệu đã có và đóng gói thành Report
  - Tạo ID báo cáo duy nhất theo timestamp
  - Tự động tạo summary text tổng hợp
"""

import sys
import os
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.report import Report
from models.alert import Alert
from models.aiResult import AIResult


class ReportGenerator:
    """
    Tạo Report object từ dữ liệu thu thập được trong một phiên giám sát.
    """

    @staticmethod
    def generate(
        alerts: List[Alert],
        statistics: Dict[str, Any],
        aiResult: Optional[AIResult] = None,
        title: str = "Network Sentinel Security Report"
    ) -> Report:
        """
        Tạo một Report object từ alerts, statistics và AI analysis.

        Args:
            alerts (List[Alert]): Danh sách Alert phát hiện được
            statistics (Dict): Thống kê traffic (từ Traffic.getStatistics())
            aiResult (Optional[AIResult]): Kết quả AI analysis (có thể None)
            title (str): Tiêu đề báo cáo

        Returns:
            Report: Báo cáo bảo mật đầy đủ
        """
        now = datetime.now()

        # Tạo ID duy nhất cho báo cáo
        report_id = f"rpt-{now.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        # Tự động tạo summary text
        summary = ReportGenerator._buildSummary(alerts, statistics, aiResult)

        return Report(
            id=report_id,
            timestamp=now,
            alerts=alerts,
            aiResult=aiResult,
            statistics=statistics,
            title=title,
            summary=summary
        )

    @staticmethod
    def _buildSummary(
        alerts: List[Alert],
        statistics: Dict[str, Any],
        aiResult: Optional[AIResult]
    ) -> str:
        """
        Tạo văn bản tóm tắt báo cáo tự động.

        Args:
            alerts: Danh sách Alert
            statistics: Thống kê traffic
            aiResult: Kết quả AI (có thể None)

        Returns:
            str: Văn bản tóm tắt
        """
        total_packets = statistics.get("totalPackets", 0)
        duration = statistics.get("durationSeconds", 0)
        total_alerts = len(alerts)

        # Đếm theo severity
        severity_counts = {}
        for alert in alerts:
            sev = alert.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Danh sách loại tấn công
        attack_types = list({a.attackType for a in alerts})

        # Danh sách IP đáng ngờ
        suspicious_ips = list({a.sourceIp for a in alerts})[:5]

        lines = [
            f"Báo cáo bảo mật mạng tự động – {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            f"",
            f"TỔNG QUAN:",
            f"  - Thời gian giám sát: {duration:.1f} giây",
            f"  - Tổng gói tin phân tích: {total_packets:,}",
            f"  - Tổng cảnh báo phát hiện: {total_alerts}",
        ]

        if severity_counts:
            sev_str = ", ".join(f"{sev}: {count}" for sev, count in severity_counts.items())
            lines.append(f"  - Phân loại mức độ: {sev_str}")

        if attack_types:
            lines.append(f"  - Loại tấn công phát hiện: {', '.join(attack_types)}")

        if suspicious_ips:
            lines.append(f"  - IP đáng ngờ: {', '.join(suspicious_ips)}")

        if aiResult:
            lines.extend([
                f"",
                f"ĐÁNH GIÁ AI:",
                f"  - Mức độ rủi ro: {aiResult.riskLevel.upper()}",
                f"  - Độ tin cậy AI: {aiResult.confidence:.1%}",
                f"  - Nhận định: {aiResult.explanation}",
                f"  - Khuyến nghị: {aiResult.recommendation}",
            ])
        else:
            lines.extend([
                f"",
                f"AI ANALYSIS: Không khả dụng trong phiên này.",
            ])

        if total_alerts == 0:
            lines.extend([f"", f"KẾT LUẬN: Không phát hiện mối đe dọa bảo mật nào."])
        elif severity_counts.get("critical", 0) > 0:
            lines.extend([f"", f"KẾT LUẬN: ⚠️ Phát hiện mối đe dọa NGHIÊM TRỌNG. Cần xử lý ngay!"])
        else:
            lines.extend([f"", f"KẾT LUẬN: Phát hiện một số dấu hiệu bất thường, cần theo dõi."])

        return "\n".join(lines)
