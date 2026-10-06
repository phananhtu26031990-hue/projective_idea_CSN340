"""
NetworkSentinelAI – Entry Point
=================================
File chính khởi động và điều phối toàn bộ hệ thống IDS.

Pipeline xử lý (mỗi gói tin):
  ┌──────────────────────────────────────────────────────────────────┐
  │  Network Traffic (card mạng / file pcap)                        │
  │          ↓                                                       │
  │  PacketCapture → PySharkAdapter → Packet object                 │
  │          ↓                                                       │
  │  TrafficAnalyzer.processPacket()                                │
  │          ↓ (khi cửa sổ đầy → traffic window đã đóng)           │
  │  RuleEngine.analyze(traffic) → List[Alert]                      │
  │          ↓                                                       │
  │  AlertManager.addAlerts()                                        │
  │          ↓ (song song)                                          │
  │  ┌────────────────┐    ┌────────────────────┐                   │
  │  │ Logger.log()   │    │ SecurityAnalyzer    │                   │
  │  │ (ghi ngay!)    │    │ .analyze() (AI)     │                   │
  │  └────────────────┘    └────────────────────┘                   │
  │          ↓ (sau khi AI xong hoặc timeout)                       │
  │  NotificationManager.notify() [critical alerts]                  │
  │          ↓                                                       │
  │  ReportGenerator + ReportExporter (khi kết thúc phiên)          │
  └──────────────────────────────────────────────────────────────────┘

Thiết kế quan trọng:
  - Logger chạy NGAY LẬP TỨC, KHÔNG đợi AI
  - AI chạy trong thread riêng (concurrent)
  - Mọi exception đều được catch → hệ thống không crash
  - Ctrl+C → dọn dẹp graceful (đóng file, xuất report cuối)

Cách chạy:
  # Live capture:
  python src/main.py

  # Đọc file pcap (simulation):
  python src/main.py --file path/to/capture.pcap

  # Dry run (giả lập gói tin):
  python src/main.py --dry-run
"""

import argparse
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional

# ── Thêm thư mục src vào Python path ──────────────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config.configLoader import ConfigLoader
from utils.helpers import setupLogging, formatBytes, formatDuration

from models.packet import Packet
from models.traffic import Traffic
from models.alert import Alert
from models.aiResult import AIResult
from models.report import Report

from trafficProcessing.trafficAnalyzer import TrafficAnalyzer
from detection.ruleEngine import RuleEngine
from alert_management.alertManager import AlertManager
from storage.logger import Logger
from ai_security.securityAnalyzer import SecurityAnalyzer
from report.reportGenerator import ReportGenerator
from report.reportExporter import ReportExporter
from notification.notificationManager import NotificationManager

logger = logging.getLogger(__name__)


class NetworkSentinelAI:
    """
    Lớp chính điều phối toàn bộ pipeline IDS.

    Mỗi component được khởi tạo một lần duy nhất khi start().
    Vòng lặp chính: nhận packet → xử lý → phát hiện → log/AI/notify.
    """

    def __init__(self, config_path: str = None):
        """
        Args:
            config_path (str): Đường dẫn file config.yaml.
                               Mặc định: config/config.yaml
        """
        # Load cấu hình
        self.config = ConfigLoader(config_path=config_path)

        # Thống kê runtime
        self._start_time: Optional[datetime] = None
        self._packet_count: int = 0
        self._window_count: int = 0
        self._is_running: bool = False

        # Khởi tạo các components
        self._initComponents()

    def _initComponents(self) -> None:
        """
        Khởi tạo tất cả components theo cấu hình.
        Thứ tự: Config → Analyzer → Detection → Storage → AI → Report → Notification
        """
        logger.info("Khởi tạo NetworkSentinelAI components...")

        window_size = self.config.getWindowSize()

        # Layer 4: Traffic Processing
        self.trafficAnalyzer = TrafficAnalyzer(windowSize=window_size)

        # Layer 3: Detection
        self.ruleEngine = RuleEngine(config=self.config.getAll())

        # Layer 4: Alert Management
        self.alertManager = AlertManager()

        # Layer 5: Storage (Logger)
        self.storageLogger = Logger(config=self.config.getLoggingConfig())
        self.storageLogger.setup()

        # Layer 6: AI Security
        self.securityAnalyzer = SecurityAnalyzer(config=self.config.getAIConfig())

        # Layer 7: Report
        self.reportGenerator = ReportGenerator()
        self.reportExporter = ReportExporter(output_dir="reports")

        # Layer 8: Notification
        self.notificationManager = NotificationManager(
            config=self.config.getNotificationConfig(),
            min_severity="high"
        )

        # Thread pool cho AI analysis và Notification
        self._ai_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="AIAnalysis")
        self._notif_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="Notification")

        logger.info("Tất cả components đã được khởi tạo thành công!")

    # ──────────────────────────────────────────────────────────────────────────
    # PACKET HANDLER – Đây là hàm callback được gọi mỗi khi có packet mới
    # ──────────────────────────────────────────────────────────────────────────

    def handlePacket(self, packet: Packet) -> None:
        """
        Xử lý một Packet mới đến từ PacketCapture.

        Đây là trái tim của pipeline:
          1. Đưa packet vào TrafficAnalyzer
          2. Nếu cửa sổ vừa đóng → phân tích traffic window đó
          3. Ghi log NGAY, AI chạy song song

        Args:
            packet (Packet): Gói tin vừa bắt được
        """
        self._packet_count += 1

        # Xử lý packet và kiểm tra cửa sổ có bị đóng không
        closed_traffic = self.trafficAnalyzer.processPacket(packet)

        if closed_traffic is not None:
            # Cửa sổ traffic vừa đóng → phân tích ngay
            self._window_count += 1
            self._processTrafficWindow(closed_traffic)

    def _processTrafficWindow(self, traffic: Traffic) -> None:
        """
        Xử lý một Traffic window vừa đóng:
          1. Chạy detection rules → lấy alerts
          2. Lưu alerts vào AlertManager
          3. Ghi log NGAY (không đợi AI)
          4. Gửi AI analysis trong thread riêng (song song)
          5. Gửi notification cho critical alerts

        Args:
            traffic (Traffic): Traffic window vừa đóng cần phân tích
        """
        stats = traffic.getStatistics()
        duration = stats.get("durationSeconds", 0)
        packet_count = stats.get("totalPackets", 0)

        logger.info(
            f"─── Cửa sổ #{self._window_count} ───────────────────────────\n"
            f"    Gói tin: {packet_count} | Thời gian: {formatDuration(duration)} | "
            f"Traffic: {formatBytes(stats.get('totalByte', 0))}"
        )

        # ── Bước 1: Chạy Detection Rules ──────────────────────────────────────
        alerts: List[Alert] = self.ruleEngine.analyze(traffic)

        if not alerts:
            logger.info("    ✅ Không phát hiện mối đe dọa trong cửa sổ này")
            return

        # ── Bước 2: Lưu vào AlertManager ─────────────────────────────────────
        self.alertManager.addAlerts(alerts)

        # ── Bước 3: GHI LOG NGAY (TRƯỚC KHI đợi AI) ──────────────────────────
        # QUAN TRỌNG: Trong Security, Log là bằng chứng pháp lý.
        # KHÔNG BAO GIỜ delay việc ghi log vì phải đợi AI.
        self.storageLogger.logAlerts(alerts)
        logger.info(f"    📁 Đã ghi {len(alerts)} alert(s) vào log")

        # ── Bước 4: AI Analysis SONG SONG (không block) ───────────────────────
        # Gửi vào thread pool và KHÔNG đợi kết quả ngay
        ai_future = self._ai_executor.submit(self._runAIAnalysis, alerts, stats)

        # ── Bước 5: Gửi Notification cho critical alerts (không đợi AI) ───────
        critical_alerts = [a for a in alerts if a.severity == "critical"]
        if critical_alerts:
            self._notif_executor.submit(self._sendNotifications, critical_alerts)

        # In tóm tắt alerts ra màn hình
        for alert in alerts:
            logger.warning(alert.getMessage())

    def _runAIAnalysis(
        self, alerts: List[Alert], stats: dict
    ) -> Optional[AIResult]:
        """
        Chạy AI analysis trong thread riêng.
        Được gọi bởi ThreadPoolExecutor → không block pipeline chính.

        Args:
            alerts: Danh sách Alert cần phân tích
            stats: Thống kê traffic

        Returns:
            Optional[AIResult]: Kết quả AI, hoặc None nếu lỗi
        """
        try:
            ai_result = self.securityAnalyzer.analyze(alerts)
            if ai_result:
                logger.info(
                    f"    🤖 AI Analysis: Risk={ai_result.riskLevel.upper()}, "
                    f"Confidence={ai_result.confidence:.2%}"
                )
            return ai_result
        except Exception as e:
            logger.error(f"AI Analysis thread lỗi: {e}")
            return None

    def _sendNotifications(self, alerts: List[Alert]) -> None:
        """
        Gửi notification trong thread riêng để không block pipeline.

        Args:
            alerts: Danh sách Alert cần gửi thông báo
        """
        try:
            for alert in alerts:
                self.notificationManager.notify(alert)
        except Exception as e:
            logger.error(f"Notification thread lỗi: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # START / STOP
    # ──────────────────────────────────────────────────────────────────────────

    def start(self, pcap_file: str = None, dry_run: bool = False) -> None:
        """
        Khởi động hệ thống IDS.

        Args:
            pcap_file (str): Nếu cung cấp → đọc từ file .pcap thay vì live capture
            dry_run (bool): Nếu True → chạy với dữ liệu giả lập, không cần card mạng
        """
        self._start_time = datetime.now()
        self._is_running = True

        logger.info("=" * 60)
        logger.info("  🛡️  NetworkSentinelAI – Hệ thống IDS đang khởi động  🛡️")
        logger.info("=" * 60)
        logger.info(f"  Thời gian bắt đầu: {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"  Cửa sổ phân tích: {self.config.getWindowSize()} giây")
        logger.info(f"  Interface: {self.config.getInterface()}")
        logger.info(f"  BPF Filter: {self.config.getBpfFilter()}")
        logger.info("=" * 60)

        try:
            if dry_run:
                self._runDryRun()
            elif pcap_file:
                self._runFileCapture(pcap_file)
            else:
                self._runLiveCapture()
        except KeyboardInterrupt:
            logger.info("\n🛑 Dừng bởi người dùng (Ctrl+C)")
        except Exception as e:
            logger.error(f"Lỗi nghiêm trọng: {e}", exc_info=True)
        finally:
            self.stop()

    def _runLiveCapture(self) -> None:
        """Chạy live capture từ card mạng thật."""
        from capture.packetCapture import PacketCapture

        interface = self.config.getInterface()
        bpf_filter = self.config.getBpfFilter()

        capture = PacketCapture(interface=interface, bpfFilter=bpf_filter)
        logger.info(f"🔴 Đang bắt gói tin từ interface '{interface}'... (Ctrl+C để dừng)")
        capture.startCapture(callback=self.handlePacket)

    def _runFileCapture(self, pcap_file: str) -> None:
        """Đọc và phân tích file .pcap."""
        from capture.packetCapture import PacketCapture

        logger.info(f"📂 Đọc file pcap: {pcap_file}")
        capture = PacketCapture(bpfFilter=self.config.getBpfFilter())
        capture.startFileCapture(pcap_file=pcap_file, callback=self.handlePacket)

    def _runDryRun(self) -> None:
        """
        Chạy giả lập với dữ liệu mock để test pipeline không cần card mạng.
        Tạo ra các gói tin giả lập các loại tấn công khác nhau.
        """
        from parsing.packetParser import PacketParser
        from datetime import timedelta

        logger.info("🧪 Chạy chế độ DRY RUN (giả lập dữ liệu)...")
        base_time = datetime.now()
        window_size = self.config.getWindowSize()
        packets = []

        # ── Giả lập SYN Flood từ 192.168.100.5 ────────────────────────────────
        for i in range(150):
            p = PacketParser.fromArgs(
                srcIp="192.168.100.5",
                dstIp="10.0.0.1",
                protocol="TCP",
                srcPort=40000 + i,
                dstPort=80,
                tcpFlags=["SYN"],
                length=64,
                timestamp=base_time + timedelta(seconds=i * 0.05)
            )
            packets.append(p)

        # ── Giả lập Port Scan từ 10.20.30.40 ──────────────────────────────────
        for port in range(1, 100):
            p = PacketParser.fromArgs(
                srcIp="10.20.30.40",
                dstIp="192.168.1.1",
                protocol="TCP",
                srcPort=50000,
                dstPort=port,
                tcpFlags=["SYN"],
                length=40,
                timestamp=base_time + timedelta(seconds=port * 0.1)
            )
            packets.append(p)

        # ── Giả lập traffic bình thường ────────────────────────────────────────
        for i in range(20):
            p = PacketParser.fromArgs(
                srcIp=f"172.16.0.{i+1}",
                dstIp="8.8.8.8",
                protocol="UDP",
                srcPort=12000 + i,
                dstPort=53,
                length=128,
                timestamp=base_time + timedelta(seconds=i * 0.2)
            )
            packets.append(p)

        # Sắp xếp theo timestamp
        packets.sort(key=lambda p: p.timestamp)

        logger.info(f"Giả lập {len(packets)} gói tin...")
        for packet in packets:
            if not self._is_running:
                break
            self.handlePacket(packet)

        # Đảm bảo xử lý cửa sổ cuối (có thể chưa đầy)
        final_traffic = self.trafficAnalyzer.getCurrentTraffic()
        if final_traffic and final_traffic.totalPackets > 0:
            self.trafficAnalyzer.closeTraffic()
            self._window_count += 1
            self._processTrafficWindow(final_traffic)

        logger.info("DRY RUN hoàn tất.")

    def stop(self) -> None:
        """
        Dừng hệ thống và thực hiện cleanup:
          1. Xử lý cửa sổ traffic cuối
          2. Đợi AI analysis hoàn tất
          3. Tạo báo cáo tổng kết
          4. Đóng tất cả file/connection
        """
        self._is_running = False
        logger.info("\n" + "=" * 60)
        logger.info("  🔒 NetworkSentinelAI đang dừng...")
        logger.info("=" * 60)

        # Xử lý cửa sổ cuối (có thể chưa đầy)
        final_traffic = self.trafficAnalyzer.getCurrentTraffic()
        if final_traffic and final_traffic.totalPackets > 0:
            logger.info("Xử lý cửa sổ traffic cuối...")
            self.trafficAnalyzer.closeTraffic()
            self._processTrafficWindow(final_traffic)

        # Đợi tất cả AI analysis và Notification thread hoàn tất
        logger.info("Đợi AI analysis và các thông báo hoàn tất...")
        self._ai_executor.shutdown(wait=True, cancel_futures=False)
        self._notif_executor.shutdown(wait=True, cancel_futures=False)

        # Tạo báo cáo tổng kết
        self._generateFinalReport()

        # Đóng tất cả storage
        self.storageLogger.close()

        # Thống kê cuối
        end_time = datetime.now()
        duration = (end_time - self._start_time).total_seconds() if self._start_time else 0
        alert_stats = self.alertManager.getSeverityCount()

        logger.info("─" * 60)
        logger.info("  📊 THỐNG KÊ PHIÊN LÀM VIỆC")
        logger.info("─" * 60)
        logger.info(f"  Tổng thời gian chạy  : {formatDuration(duration)}")
        logger.info(f"  Tổng gói tin xử lý   : {self._packet_count:,}")
        logger.info(f"  Cửa sổ phân tích     : {self._window_count}")
        logger.info(f"  Tổng alert phát hiện : {self.alertManager.alertCount}")
        logger.info(f"  Critical alerts      : {alert_stats.get('critical', 0)}")
        logger.info(f"  High alerts          : {alert_stats.get('high', 0)}")
        logger.info("─" * 60)

    def _generateFinalReport(self) -> None:
        """Tạo và xuất báo cáo tổng kết phiên giám sát."""
        all_alerts = self.alertManager.getAll()
        if not all_alerts:
            logger.info("Không có alert nào → bỏ qua tạo báo cáo")
            return

        # Tổng hợp statistics
        history = self.trafficAnalyzer.trafficHistory
        total_packets = sum(t.totalPackets for t in history)
        total_bytes = sum(t.totalByte for t in history)
        total_duration = sum(t.getDuration() for t in history)

        summary_stats = {
            "totalPackets": total_packets,
            "totalByte": total_bytes,
            "totalBytesFormatted": formatBytes(total_bytes),
            "durationSeconds": round(total_duration, 2),
            "durationFormatted": formatDuration(total_duration),
            "totalWindows": self._window_count,
            "totalAlerts": self.alertManager.alertCount,
        }
        summary_stats.update(self.alertManager.getStats())

        # Tạo report
        report = ReportGenerator.generate(
            alerts=all_alerts,
            statistics=summary_stats,
            aiResult=None,  # AI result cá nhân đã được ghi theo từng window
            title="NetworkSentinelAI – Final Security Report"
        )

        # Xuất ra TXT và HTML (PDF nếu reportlab có)
        results = self.reportExporter.exportAll(report)
        for fmt, path in results.items():
            if path:
                logger.info(f"📄 Báo cáo {fmt.upper()}: {path}")

        # Gửi report về điện thoại qua Telegram (nếu đã cấu hình)
        self._sendReportViaTelegram(results)

    def _sendReportViaTelegram(self, report_files: dict) -> None:
        """
        Gửi file Report PDF/TXT qua Telegram Bot API.

        Được gọi cuối phiên sau khi xuất report.
        Nếu Telegram chưa bật hoặc không có file → bỏ qua.

        Args:
            report_files (dict): {"pdf": path, "txt": path, "html": path}
        """
        import json as _json
        import urllib.request as _urllib

        notif_config = self.config.getNotificationConfig()
        tg_config = notif_config.get("telegram", {})

        if not tg_config.get("enabled") or not tg_config.get("token"):
            return

        token = tg_config["token"]
        chat_id = str(tg_config.get("chat_id", ""))
        if not chat_id:
            return

        # Ưu tiên gửi PDF, nếu không có thì TXT
        file_path = report_files.get("pdf") or report_files.get("txt")
        if not file_path or not os.path.exists(file_path):
            logger.warning("Không tìm thấy file report để gửi Telegram")
            return

        try:
            url = f"https://api.telegram.org/bot{token}/sendDocument"
            filename = os.path.basename(file_path)

            # Tóm tắt thống kê để đưa vào caption
            alert_stats = self.alertManager.getSeverityCount()
            caption = (
                f"📊 *NetworkSentinelAI Security Report*\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"🔴 Critical: {alert_stats.get('critical', 0)}\n"
                f"🟠 High: {alert_stats.get('high', 0)}\n"
                f"🟡 Medium: {alert_stats.get('medium', 0)}\n"
                f"🟢 Low: {alert_stats.get('low', 0)}\n"
                f"📦 Gói tin: {self._packet_count:,} | ⏱ Windows: {self._window_count}"
            )

            # Multipart form data để upload file
            boundary = "NetworkSentinelBoundary2026"

            with open(file_path, "rb") as f:
                file_data = f.read()

            # Build multipart body
            body_parts = []
            body_parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="chat_id"\r\n\r\n'
                f"{chat_id}\r\n"
            )
            body_parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="caption"\r\n\r\n'
                f"{caption}\r\n"
            )
            body_parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="parse_mode"\r\n\r\n'
                f"Markdown\r\n"
            )
            body_parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            )

            body = (
                "".join(body_parts).encode("utf-8")
                + file_data
                + f"\r\n--{boundary}--\r\n".encode("utf-8")
            )

            req = _urllib.Request(
                url, data=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(body)),
                }
            )

            with _urllib.urlopen(req, timeout=30) as resp:
                result = _json.loads(resp.read().decode("utf-8"))
                if result.get("ok"):
                    logger.info(f"📱 Đã gửi report PDF qua Telegram: {filename}")
                else:
                    logger.warning(f"Telegram sendDocument lỗi: {result.get('description')}")

        except Exception as e:
            logger.error(f"Lỗi gửi report qua Telegram: {e}")



# ────────────────────────────────────────────────────────────────────────────────
# MAIN
# ────────────────────────────────────────────────────────────────────────────────

def parseArgs() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="NetworkSentinelAI – IDS với AI cục bộ",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python src/main.py                       # Live capture
  python src/main.py --dry-run             # Giả lập (không cần card mạng)
  python src/main.py --file capture.pcap   # Đọc file pcap
  python src/main.py --config myconfig.yaml
        """
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Chạy với dữ liệu giả lập (không cần card mạng, dùng cho test)"
    )
    parser.add_argument(
        "--file", metavar="PCAP_FILE",
        help="Đường dẫn file .pcap để phân tích offline"
    )
    parser.add_argument(
        "--config", metavar="CONFIG_PATH", default=None,
        help="Đường dẫn file config.yaml (mặc định: config/config.yaml)"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Mức độ chi tiết của log (mặc định: INFO)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parseArgs()

    # Cấu hình logging cho toàn bộ ứng dụng
    setupLogging(
        log_level=args.log_level,
        log_file="logs/sentinel.log"
    )

    # Khởi tạo và chạy hệ thống
    sentinel = NetworkSentinelAI(config_path=args.config)
    sentinel.start(
        pcap_file=args.file,
        dry_run=args.dry_run
    )
