"""
ReportExporter – Xuất báo cáo ra file
========================================
Xuất Report object sang các định dạng file khác nhau:
  - TXT: Plain text, đơn giản, đọc được ở mọi đâu
  - HTML: Định dạng web, có màu sắc và bảng biểu
  - PDF: Định dạng chuyên nghiệp (cần thư viện reportlab)

Thiết kế:
  - Mỗi phương thức export độc lập, không phụ thuộc nhau
  - Nếu reportlab không cài → PDF bị skip, TXT/HTML vẫn hoạt động
  - File được lưu vào thư mục reports/ với tên chứa report ID và timestamp
"""

import logging
import os
import sys
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.report import Report

logger = logging.getLogger(__name__)


class ReportExporter:
    """
    Xuất Report object sang các định dạng file.
    """

    def __init__(self, output_dir: str = "reports"):
        """
        Args:
            output_dir (str): Thư mục lưu báo cáo
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def _getFilePath(self, report: Report, extension: str) -> str:
        """Tạo đường dẫn file duy nhất cho báo cáo."""
        filename = f"{report.id}.{extension}"
        return os.path.join(self.output_dir, filename)

    # ───────────────────────────────────────────────────────
    # TXT Export
    # ───────────────────────────────────────────────────────

    def exportTXT(self, report: Report) -> Optional[str]:
        """
        Xuất báo cáo ra file plain text.

        Args:
            report (Report): Báo cáo cần xuất

        Returns:
            Optional[str]: Đường dẫn file đã tạo, hoặc None nếu lỗi
        """
        file_path = self._getFilePath(report, "txt")
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write(f"  {report.title.upper()}\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"Report ID : {report.id}\n")
                f.write(f"Generated : {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 70 + "\n\n")

                # Summary
                f.write("SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(report.summary + "\n\n")

                # Statistics
                f.write("TRAFFIC STATISTICS\n")
                f.write("-" * 40 + "\n")
                for key, value in report.statistics.items():
                    f.write(f"  {key}: {value}\n")
                f.write("\n")

                # Alerts
                f.write(f"ALERTS ({len(report.alerts)} total)\n")
                f.write("-" * 40 + "\n")
                for alert in report.alerts:
                    f.write(f"\n  [{alert.severity.upper()} #{alert.id}] {alert.attackType}\n")
                    f.write(f"  Source: {alert.sourceIp} → Destination: {alert.destinationIp}\n")
                    f.write(f"  Rule: {alert.ruleName} | Confidence: {alert.confidence:.2%}\n")
                    f.write(f"  Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"  Description: {alert.description}\n")

                # AI Result
                if report.aiResult:
                    f.write("\nAI ANALYSIS\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"  Risk Level: {report.aiResult.riskLevel.upper()}\n")
                    f.write(f"  Confidence: {report.aiResult.confidence:.2%}\n")
                    f.write(f"  Explanation: {report.aiResult.explanation}\n")
                    f.write(f"  Recommendation: {report.aiResult.recommendation}\n")

                f.write("\n" + "=" * 70 + "\n")
                f.write("  END OF REPORT\n")
                f.write("=" * 70 + "\n")

            logger.info(f"TXT report: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Lỗi xuất TXT: {e}")
            return None

    # ───────────────────────────────────────────────────────
    # HTML Export
    # ───────────────────────────────────────────────────────

    def exportHTML(self, report: Report) -> Optional[str]:
        """
        Xuất báo cáo ra file HTML với màu sắc và bảng biểu.

        Args:
            report (Report): Báo cáo cần xuất

        Returns:
            Optional[str]: Đường dẫn file đã tạo
        """
        file_path = self._getFilePath(report, "html")
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
        }

        try:
            alerts_html = ""
            for alert in report.alerts:
                color = severity_colors.get(alert.severity.lower(), "#6c757d")
                alerts_html += f"""
                <tr>
                    <td><span style="color:{color};font-weight:bold">#{alert.id} {alert.severity.upper()}</span></td>
                    <td>{alert.attackType}</td>
                    <td>{alert.sourceIp}</td>
                    <td>{alert.destinationIp}</td>
                    <td>{alert.confidence:.2%}</td>
                    <td>{alert.timestamp.strftime('%H:%M:%S')}</td>
                </tr>"""

            ai_html = ""
            if report.aiResult:
                risk_color = severity_colors.get(report.aiResult.riskLevel.lower(), "#6c757d")
                ai_html = f"""
                <div class="ai-section">
                    <h2>🤖 AI Security Analysis</h2>
                    <p><strong>Risk Level:</strong> <span style="color:{risk_color}">
                        {report.aiResult.riskLevel.upper()}</span>
                        (Confidence: {report.aiResult.confidence:.2%})</p>
                    <p><strong>Explanation:</strong> {report.aiResult.explanation}</p>
                    <p><strong>Recommendation:</strong> {report.aiResult.recommendation}</p>
                </div>"""

            stats_rows = ""
            for key, value in report.statistics.items():
                stats_rows += f"<tr><td>{key}</td><td>{value}</td></tr>"

            html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>{report.title}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f8f9fa; color: #333; }}
        h1 {{ color: #1a237e; border-bottom: 3px solid #1a237e; padding-bottom: 10px; }}
        h2 {{ color: #283593; margin-top: 30px; }}
        .meta {{ background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .summary {{ background: #fff; padding: 20px; border-left: 4px solid #1565c0; border-radius: 4px; white-space: pre-line; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #1a237e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #e0e0e0; }}
        tr:hover {{ background: #f5f5f5; }}
        .ai-section {{ background: #e8f5e9; padding: 20px; border-radius: 8px; border-left: 4px solid #2e7d32; }}
        .footer {{ text-align: center; margin-top: 40px; color: #888; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>🛡️ {report.title}</h1>
    <div class="meta">
        <strong>Report ID:</strong> {report.id} &nbsp;|&nbsp;
        <strong>Generated:</strong> {report.timestamp.strftime('%d/%m/%Y %H:%M:%S')}
    </div>

    <h2>📋 Summary</h2>
    <div class="summary">{report.summary}</div>

    <h2>📊 Traffic Statistics</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        {stats_rows}
    </table>

    <h2>⚠️ Security Alerts ({len(report.alerts)})</h2>
    <table>
        <tr><th>ID & Severity</th><th>Attack Type</th><th>Source IP</th>
            <th>Destination</th><th>Confidence</th><th>Time</th></tr>
        {alerts_html if alerts_html else '<tr><td colspan="6" style="text-align:center">No alerts</td></tr>'}
    </table>

    {ai_html}

    <div class="footer">Generated by NetworkSentinelAI | {datetime.now().strftime('%Y')}</div>
</body>
</html>"""

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html)

            logger.info(f"HTML report: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Lỗi xuất HTML: {e}")
            return None

    # ───────────────────────────────────────────────────────
    # PDF Export
    # ───────────────────────────────────────────────────────

    def exportPDF(self, report: Report) -> Optional[str]:
        """
        Xuất báo cáo ra file PDF (cần thư viện reportlab).

        Nếu reportlab chưa được cài đặt, sẽ tự động xuất TXT thay thế.

        Args:
            report (Report): Báo cáo cần xuất

        Returns:
            Optional[str]: Đường dẫn file đã tạo
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                            Table, TableStyle, HRFlowable)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            logger.warning("reportlab chưa được cài. Chuyển sang xuất TXT. Cài: pip install reportlab")
            return self.exportTXT(report)

        file_path = self._getFilePath(report, "pdf")
        try:
            doc = SimpleDocTemplate(file_path, pagesize=A4,
                                    topMargin=2*cm, bottomMargin=2*cm,
                                    leftMargin=2*cm, rightMargin=2*cm)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = ParagraphStyle("title", parent=styles["Title"],
                                         textColor=colors.HexColor("#1a237e"), fontSize=18)
            story.append(Paragraph(report.title, title_style))
            story.append(Spacer(1, 0.3*cm))
            story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a237e")))
            story.append(Spacer(1, 0.3*cm))

            # Meta
            story.append(Paragraph(
                f"<b>Report ID:</b> {report.id} &nbsp; | &nbsp; "
                f"<b>Generated:</b> {report.timestamp.strftime('%d/%m/%Y %H:%M:%S')}",
                styles["Normal"]
            ))
            story.append(Spacer(1, 0.5*cm))

            # Summary
            story.append(Paragraph("SUMMARY", styles["Heading2"]))
            for line in report.summary.split("\n"):
                story.append(Paragraph(line or "&nbsp;", styles["Normal"]))
            story.append(Spacer(1, 0.5*cm))

            # Alerts Table
            story.append(Paragraph(f"ALERTS ({len(report.alerts)})", styles["Heading2"]))
            alert_data = [["#", "Severity", "Attack", "Source IP", "Target IP", "Confidence"]]
            sev_colors = {"critical": colors.red, "high": colors.orange,
                          "medium": colors.yellow, "low": colors.green}
            for alert in report.alerts:
                alert_data.append([
                    str(alert.id),
                    alert.severity.upper(),
                    alert.attackType,
                    alert.sourceIp,
                    alert.destinationIp,
                    f"{alert.confidence:.2%}"
                ])

            table = Table(alert_data, colWidths=[1*cm, 2.5*cm, 3.5*cm, 3.5*cm, 3.5*cm, 2.5*cm])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4ff")]),
            ]))
            story.append(table)
            story.append(Spacer(1, 0.5*cm))

            # AI Result
            if report.aiResult:
                story.append(Paragraph("AI SECURITY ANALYSIS", styles["Heading2"]))
                story.append(Paragraph(
                    f"<b>Risk Level:</b> {report.aiResult.riskLevel.upper()} | "
                    f"<b>Confidence:</b> {report.aiResult.confidence:.2%}",
                    styles["Normal"]
                ))
                story.append(Paragraph(f"<b>Explanation:</b> {report.aiResult.explanation}", styles["Normal"]))
                story.append(Paragraph(f"<b>Recommendation:</b> {report.aiResult.recommendation}", styles["Normal"]))

            doc.build(story)
            logger.info(f"PDF report: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Lỗi xuất PDF: {e}")
            return None

    def exportAll(self, report: Report) -> dict:
        """
        Xuất báo cáo ra tất cả các định dạng.

        Args:
            report (Report): Báo cáo cần xuất

        Returns:
            dict: {"txt": path, "html": path, "pdf": path}
        """
        return {
            "txt": self.exportTXT(report),
            "html": self.exportHTML(report),
            "pdf": self.exportPDF(report),
        }
