# 🛡️ NetworkSentinelAI

**Hệ thống phát hiện xâm nhập mạng (IDS) kết hợp Rule-Based và AI cục bộ (Ollama)**

---

## 📖 Mục lục

1. [Giới thiệu](#giới-thiệu)
2. [Kiến trúc tổng thể](#kiến-trúc-tổng-thể)
3. [Luồng xử lý (Pipeline)](#luồng-xử-lý-pipeline)
4. [Chi tiết từng Layer](#chi-tiết-từng-layer)
   - [Layer 1: Capture](#layer-1--capture-layer)
   - [Layer 2: Parsing](#layer-2--parsing-layer)
   - [Layer 3: Data Model](#layer-3--data-model-layer)
   - [Layer 4: Traffic Processing](#layer-4--traffic-processing-layer)
   - [Layer 5: Detection](#layer-5--detection-layer)
   - [Layer 6: Alert Management](#layer-6--alert-management-layer)
   - [Layer 7: Storage](#layer-7--storage-layer)
   - [Layer 8: AI Security](#layer-8--ai-security-layer)
   - [Layer 9: Report](#layer-9--report-layer)
   - [Layer 10: Notification](#layer-10--notification-layer)
5. [Các loại tấn công được phát hiện](#các-loại-tấn-công-được-phát-hiện)
6. [Cấu hình](#cấu-hình)
7. [Cài đặt và chạy](#cài-đặt-và-chạy)
8. [Tests](#tests)
9. [Thiết kế quan trọng](#thiết-kế-quan-trọng)

---

## Giới thiệu

NetworkSentinelAI là một **IDS (Intrusion Detection System)** hoạt động ở tầng mạng, phát hiện các cuộc tấn công phổ biến theo thời gian thực bằng:
- **Rule-based detection**: Phân tích gói tin theo quy tắc cố định (nhanh, đáng tin cậy)
- **AI cục bộ (Ollama)**: Phân tích ngữ nghĩa sâu hơn, không gửi dữ liệu ra ngoài

---

## Kiến trúc tổng thể

```
NetworkSentinelAI/
│
├── src/
│   ├── capture/             # Layer 1: Bắt gói tin từ card mạng
│   │   ├── packetCapture.py      # Live capture / file capture
│   │   └── pysharkAdapter.py    # Adapter: PyShark → Packet model
│   │
│   ├── parsing/             # Layer 2: Xây dựng Packet từ dict/args
│   │   └── packetParser.py
│   │
│   ├── models/              # Layer 3: Data Model
│   │   ├── packet.py        # Đại diện 1 gói tin
│   │   ├── traffic.py       # Đại diện window traffic
│   │   ├── alert.py         # Cảnh báo bảo mật
│   │   ├── aiResult.py      # Kết quả phân tích AI
│   │   └── report.py        # Báo cáo tổng hợp
│   │
│   ├── trafficProcessing/   # Layer 4: Gom gói tin theo cửa sổ thời gian
│   │   └── trafficAnalyzer.py
│   │
│   ├── detection/           # Layer 5: Phát hiện tấn công
│   │   ├── ruleInterface.py # Interface (ABC) cho rules
│   │   ├── ruleEngine.py    # Điều phối tất cả rules
│   │   └── rules/
│   │       ├── syn_flood/   # SYN Flood detection
│   │       ├── ack_flood/   # ACK Flood detection
│   │       ├── port_scan/   # Port Scan detection
│   │       └── icmp_tunnel/ # ICMP Tunneling detection
│   │
│   ├── alert_management/    # Layer 6: Quản lý Alert
│   │   └── alertManager.py
│   │
│   ├── storage/             # Layer 7: Ghi log (CSV/JSON/SQLite)
│   │   ├── logger.py
│   │   ├── csvFormatter.py
│   │   ├── jsonFormatter.py
│   │   └── databaseFormatter.py
│   │
│   ├── ai_security/         # Layer 8: Phân tích AI cục bộ (Ollama)
│   │   ├── securityAnalyzer.py
│   │   └── local_model/
│   │       └── ollamaClient.py
│   │
│   ├── report/              # Layer 9: Tạo và xuất báo cáo
│   │   ├── reportGenerator.py
│   │   └── reportExporter.py  # PDF / TXT / HTML
│   │
│   ├── notification/        # Layer 10: Thông báo tức thì
│   │   ├── notificationManager.py
│   │   ├── telegramChannel.py
│   │   └── emailChannel.py
│   │
│   ├── config/              # Layer 11: Đọc cấu hình YAML
│   │   └── configLoader.py
│   │
│   ├── utils/               # Layer 12: Tiện ích chung
│   │   └── helpers.py
│   │
│   └── main.py              # ← Entry point chính
│
├── config/
│   └── config.yaml          # Cấu hình toàn bộ hệ thống
│
├── tests/                   # Unit tests (54 tests, 100% pass)
├── logs/                    # File log CSV, JSON, SQLite
├── reports/                 # Báo cáo xuất ra PDF/TXT/HTML
└── requirements.txt
```

---

## Luồng xử lý (Pipeline)

```
Network Traffic (card mạng / file .pcap)
        │
        ▼
┌─────────────────────┐
│   PacketCapture      │  → Bắt raw packet từ interface
│   + PySharkAdapter   │  → Chuyển đổi → Packet object
└─────────────────────┘
        │
        ▼
┌─────────────────────┐
│   TrafficAnalyzer    │  → Gom packet vào cửa sổ thời gian (window)
│   (Window = 10s)     │  → Khi window đầy → đóng → xử lý
└─────────────────────┘
        │ (khi window đóng)
        ▼
┌─────────────────────┐
│     RuleEngine       │  → Chạy 4 rules song song trên traffic window
│  SYN / ACK / Port / │  → Trả về List[Alert]
│  ICMP rules          │
└─────────────────────┘
        │
        ▼
┌─────────────────────┐
│    AlertManager      │  → Lưu trữ, lọc, thống kê alert
└─────────────────────┘
        │
   ┌────┴──────────────────────────┐
   │                               │
   ▼                               ▼
┌─────────────────────┐   ┌─────────────────────┐
│   Logger (ngay!)     │   │  SecurityAnalyzer    │ ← Thread riêng
│  CSV + JSON + SQLite │   │  (Ollama AI, chậm)   │   (không block)
└─────────────────────┘   └─────────────────────┘
                                   │ (nếu AI khả dụng)
                                   ▼
                           ┌─────────────────────┐
                           │      AIResult        │
                           └─────────────────────┘
        │
        ▼ (critical alerts)
┌─────────────────────┐
│ NotificationManager  │  → Telegram + Email (nếu bật)
└─────────────────────┘
        │ (khi kết thúc phiên)
        ▼
┌─────────────────────┐
│  ReportGenerator     │  → Tổng hợp Report
│  ReportExporter      │  → Xuất PDF / TXT / HTML
└─────────────────────┘
```

---

## Chi tiết từng Layer

---

### Layer 1 – Capture Layer

**Nhiệm vụ**: Bắt gói tin từ card mạng thực tế hoặc đọc file `.pcap`

**Cách hoạt động**:
- Dùng thư viện **PyShark** (wrapper của TShark/Wireshark)
- `PacketCapture` nhận callback function → mỗi gói tin → gọi callback
- `PySharkAdapter` chuyển đổi PyShark object → `Packet` nội bộ (**Adapter Pattern**)

**Tại sao dùng Adapter Pattern?**
```
PyShark (ngoài) → [PySharkAdapter] → Packet (nội bộ)
```
- Nếu thay PyShark bằng Scapy/dpkt → chỉ sửa Adapter, không sửa code khác
- Dễ mock trong unit test (không cần card mạng thật)

---

### Layer 2 – Parsing Layer

**Nhiệm vụ**: Xây dựng `Packet` object từ dữ liệu thô

**`PacketParser`** cung cấp 2 phương thức:
- `fromDict(data)` → tạo Packet từ dictionary (đọc từ JSON/CSV log)
- `fromArgs(srcIp, dstIp, ...)` → tạo Packet trực tiếp từ tham số (dùng trong test)

---

### Layer 3 – Data Model Layer

**Các model chính**:

| Model | Mô tả | Method quan trọng |
|-------|--------|-------------------|
| `Packet` | 1 gói tin mạng | `isTCP()`, `isUDP()`, `isICMP()`, `getSummary()`, `toDictionary()` |
| `Traffic` | Window gom nhiều Packet | `addPacket()`, `calculateRate()`, `getStatistics()` |
| `Alert` | Cảnh báo bảo mật | `getMessage()`, `toDictionary()` |
| `AIResult` | Kết quả phân tích AI | `toDictionary()` |
| `Report` | Báo cáo tổng hợp | `toDictionary()` |

**`Traffic` – Window concept (quan trọng)**:
```python
# Traffic tự động cập nhật startTime/endTime khi thêm packet
traffic = Traffic()
traffic.addPacket(packet1)   # startTime = packet1.timestamp
traffic.addPacket(packet2)   # endTime = packet2.timestamp (nếu mới hơn)
stats = traffic.getStatistics()
# → {"totalPackets": 2, "packetRatePps": X, "protocolCounts": {...}, ...}
```

---

### Layer 4 – Traffic Processing Layer

**Nhiệm vụ**: Gom các gói tin thành **Traffic Windows** theo thời gian

**`TrafficAnalyzer`** – Sliding Window Logic:
```
Packet stream:  [p1][p2][p3][p4][p5][p6] ...
                |← window 10s →||← window 10s →|
                  Traffic#1      Traffic#2
```

**Logic `processPacket()`**:
```python
def processPacket(self, packet):
    if self.isWindowExpired(packet):        # timestamp > startTime + 10s?
        closedTraffic = self.closeTraffic() # Lưu vào history
        self.createNewTraffic()              # Mở cửa sổ mới
    self.currentTraffic.addPacket(packet)
    return closedTraffic                    # None nếu chưa đóng
```

**Tại sao trả về `closedTraffic`?**
- Pipeline (`main.py`) biết ngay có traffic window mới để phân tích
- Không cần polling, không cần callback riêng

---

### Layer 5 – Detection Layer

**Kiến trúc Rule-Based**:
```
RuleEngine ──── Rule (ABC Interface)
                    │
                    ├── SynFloodRule
                    ├── AckFloodRule
                    ├── PortScanRule
                    └── ICMPTunnelRule
```

**`Rule` Interface (ABC)**:
```python
class Rule(ABC):
    @property
    @abstractmethod
    def ruleName(self) -> str: ...

    @abstractmethod
    def analyze(self, traffic: Traffic) -> List[Alert]: ...
```

**Tại sao dùng ABC?**
- **Open/Closed Principle**: Thêm rule mới không cần sửa `RuleEngine`
- **Fault tolerance**: RuleEngine wrap mỗi rule trong try/except riêng

**`RuleEngine.analyze()`** – Fault Tolerant:
```python
for rule in self.rules:
    try:
        alerts = rule.analyze(traffic)
        all_alerts.extend(alerts)
    except Exception as e:
        logger.error(f"Rule '{rule.ruleName}' bị lỗi: {e}")
        continue   # Rule lỗi → tiếp tục rule kế tiếp
```

**Logic phát hiện từng rule:**

| Rule | Tín hiệu phát hiện | Ngưỡng mặc định |
|------|--------------------|-----------------|
| `SynFloodRule` | Số gói SYN thuần (không có ACK) từ 1 IP | 100 gói/window |
| `AckFloodRule` | Số gói ACK + tỉ lệ ACK/SYN bất thường | 150 gói/window |
| `PortScanRule` | Số port đích khác nhau từ 1 IP nguồn | 50 port/window |
| `ICMPTunnelRule` | Volume ICMP cao VÀ/HOẶC payload size lớn (>100 bytes) | 30 gói/window |

---

### Layer 6 – Alert Management Layer

**`AlertManager`** – Quản lý vòng đời Alert:

```python
manager = AlertManager()
manager.addAlert(alert)                          # Thêm 1 alert
manager.addAlerts(alerts)                        # Thêm nhiều
manager.filterBySeverity("critical")             # Lọc theo mức độ
manager.filterBySourceIp("192.168.1.100")        # Lọc theo IP
manager.getTopSourceIps(top_n=5)                 # IP tấn công nhiều nhất
manager.getSeverityCount()                       # {"critical": 5, "high": 3, ...}
manager.removeBefore(cutoff_time)                # Xóa alert cũ
```

**Thứ tự ưu tiên severity**: `critical (0) > high (1) > medium (2) > low (3)`

---

### Layer 7 – Storage Layer

**Strategy Pattern**:
```
Logger ──── LogFormatter (ABC)
                │
                ├── CSVFormatter    → logs/alerts.csv
                ├── JSONFormatter   → logs/alerts.json (NDJSON)
                └── DatabaseFormatter → logs/sentinel.db (SQLite)
```

**QUAN TRỌNG – Log trước, AI sau**:
```python
# ĐÚNG (trong main.py):
self.storageLogger.logAlerts(alerts)          # GHI LOG NGAY
ai_future = executor.submit(self._runAI, ...) # AI chạy song song

# SAI:
ai_result = self.securityAnalyzer.analyze(...) # Đợi AI (có thể 30s+)
self.storageLogger.logAlerts(alerts)           # Log muộn → nguy hiểm!
```

**Tại sao NDJSON (Newline Delimited JSON)?**
```
# JSON Array (xấu – không thể append):
[{"id": 1, ...}, {"id": 2, ...}]   ← phải parse toàn bộ file

# NDJSON (tốt – append O(1)):
{"id": 1, ...}
{"id": 2, ...}   ← chỉ thêm 1 dòng mới
```

---

### Layer 8 – AI Security Layer

**`OllamaClient`** → giao tiếp với Ollama local server:
- POST `http://localhost:11434/api/generate`
- Timeout: 45 giây, retry: 2 lần
- Trả về `None` nếu Ollama không khả dụng (không crash)

**`SecurityAnalyzer`** → phân tích alert bằng LLM:

```python
# Prompt được gửi cho AI:
"""
You are a network security expert...
ALERT DETAILS:
1. [CRITICAL] SYN Flood from 192.168.1.100 → 10.0.0.1 (confidence: 0.95)

Respond with ONLY this JSON:
{
  "riskLevel": "critical",
  "confidence": 0.95,
  "explanation": "...",
  "recommendation": "..."
}
"""
```

**Fallback parsing (3 cấp độ)**:
1. Parse JSON trực tiếp
2. Tìm JSON trong markdown code block ` ```json ... ``` `
3. Heuristic: tìm từ khóa "critical", "high", "low" trong text

**Cài Ollama**:
```bash
# Tải từ https://ollama.ai/
ollama pull llama2       # Cài model
ollama serve             # Khởi động server (tự động khi cài)
```

---

### Layer 9 – Report Layer

**`ReportGenerator.generate()`** → tạo `Report` với:
- ID duy nhất: `rpt-20260819-183000-A1B2C3`
- Summary text tự động (dựa trên severity)
- Tổng hợp Alert + AIResult + Statistics

**`ReportExporter`** → xuất sang:
| Format | Thư viện | Mô tả |
|--------|----------|-------|
| **TXT** | built-in | Plain text, đọc được mọi đâu |
| **HTML** | built-in | Có màu sắc theo severity, bảng biểu |
| **PDF** | reportlab | Chuyên nghiệp; nếu không có → fallback TXT |

---

### Layer 10 – Notification Layer

**Cấu hình kênh thông báo**:
```yaml
notifications:
  telegram:
    enabled: true
    token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
  email:
    enabled: false
    smtp_server: "smtp.gmail.com"
    port: 587
    sender: "alert@company.com"
    receiver: "admin@company.com"
    password: "APP_PASSWORD"
```

**Chỉ gửi khi severity đủ cao** (mặc định: `>= high`):
```python
manager = NotificationManager(config, min_severity="high")
# → Chỉ gửi "critical" và "high" alerts, bỏ qua "medium" và "low"
```

**Định dạng Telegram Alert**:
```
🔴 [CRITICAL] SYN Flood Detected!
━━━━━━━━━━━━━━━━━━━━
🎯 Source: 192.168.1.100
🏹 Target: 10.0.0.1
📊 Confidence: 95.00%
📋 Rule: SynFloodDetection
🕐 Time: 2026-08-19 18:30:00
```

---

## Các loại tấn công được phát hiện

### 1. SYN Flood

**Nguyên lý**: Kẻ tấn công gửi ồ ạt gói SYN (khởi tạo kết nối TCP) từ IP giả mạo.
Server chờ ACK không bao giờ đến → Bảng half-open connection đầy → Từ chối dịch vụ.

```
Attacker → [SYN] (IP giả) → Server
           [SYN] (IP giả) →
           [SYN] (IP giả) →
Server →   [SYN-ACK] → IP giả (không tồn tại)
           Server chờ... chờ... timeout
           Bảng kết nối đầy → DoS!
```

**Logic phát hiện**: Đếm gói SYN thuần (SYN=1, ACK=0) từ mỗi IP nguồn.

### 2. ACK Flood

**Nguyên lý**: Gửi ồ ạt gói ACK không thuộc kết nối nào. Server phải tra bảng session để biết gói này thuộc kết nối nào → không tìm thấy → gửi RST → tốn CPU/RAM.

**Logic phát hiện**: Đếm ACK + tính tỉ lệ ACK/SYN (bình thường ≈ 1:1, tấn công >> 1).

### 3. Port Scan

**Nguyên lý**: Kẻ tấn công thử kết nối đến nhiều port để tìm dịch vụ đang mở.

```
Attacker:
  → TCP SYN to port 21 (FTP)?     → RST = closed
  → TCP SYN to port 22 (SSH)?     → SYN-ACK = OPEN!
  → TCP SYN to port 80 (HTTP)?    → SYN-ACK = OPEN!
  → TCP SYN to port 443 (HTTPS)?  → SYN-ACK = OPEN!
  → TCP SYN to port 3389 (RDP)?   → RST = closed
  ... (50+ ports trong vài giây)
```

**Logic phát hiện**: Đếm số port đích KHÁC NHAU mà 1 IP nguồn gửi đến.

### 4. ICMP Tunneling

**Nguyên lý**: Nhúng dữ liệu thật (HTTP, DNS, shell command) vào payload của gói ICMP để bypass firewall.

```
Bình thường (ping):  Payload = "Hello World" (~32 bytes)
ICMP Tunnel:         Payload = [HTTP request ẩn] (~1000+ bytes)

Firewall: "Ồ, chỉ là ICMP ping thôi, cho qua"
Attacker: "Haha, tôi đã gửi được dữ liệu qua firewall!"
```

**Logic phát hiện**: Volume ICMP cao VÀ/HOẶC payload size > 100 bytes.

---

## Cấu hình

**`config/config.yaml`**:
```yaml
# Capture
capture:
  interface: "Ethernet"    # Windows: "Ethernet", Linux: "eth0"
  filter: "ip"             # BPF filter

# Traffic Window
traffic:
  window_size: 10          # Giây

# Detection thresholds
rules:
  syn_flood:
    threshold: 100.0       # Gói SYN/window
  ack_flood:
    threshold: 150.0
  port_scan:
    threshold: 50.0        # Port khác nhau/window
  icmp_tunnel:
    threshold: 30.0        # Gói ICMP/window

# AI
security_analyzer:
  model: "llama2"
  threshold: 0.85

# Storage
logging:
  formatters:
    csv:
      enabled: true
      path: "logs/alerts.csv"
    json:
      enabled: true
      path: "logs/alerts.json"
    database:
      enabled: false

# Notification
notifications:
  telegram:
    enabled: false
    token: "YOUR_TOKEN"
    chat_id: "YOUR_CHAT_ID"
  email:
    enabled: false
```

---

## Cài đặt và chạy

### Yêu cầu hệ thống
- Python 3.8+
- Windows: Cài [Npcap](https://npcap.com/) (cho live capture)
- Linux/Mac: Wireshark/TShark

### Cài đặt

```bash
# Clone / mở thư mục dự án
cd NetworkSentinelAI

# Tạo virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac

# Cài dependencies
pip install -r requirements.txt
```

### Chạy hệ thống

```bash
# Dry Run – giả lập dữ liệu (không cần card mạng, dùng để test)
python src/main.py --dry-run

# Live Capture – capture từ card mạng thật (cần quyền admin)
python src/main.py

# Đọc file .pcap
python src/main.py --file path/to/capture.pcap

# Thay đổi config
python src/main.py --config path/to/myconfig.yaml

# Log chi tiết hơn
python src/main.py --dry-run --log-level DEBUG
```

### Cài Ollama (để bật AI)

```bash
# Tải từ https://ollama.ai/
# Sau khi cài:
ollama pull llama2           # Tải model (~4GB)
# Ollama server tự khởi động tại localhost:11434
```

---

## Tests

```bash
# Chạy tất cả tests
python -m pytest tests/ -v

# Kết quả:
# ============================= test session starts =============================
# collected 54 items
#
# tests/test_alert_manager.py ................... [ 25%]
# tests/test_detection.py .............. [ 51%]
# tests/test_models.py ..... [ 61%]
# tests/test_packet.py . [ 62%]
# tests/test_storage.py ............. [ 88%]
# tests/test_traffic_analyzer.py ..... [100%]
#
# ============================= 54 passed in 0.49s ==============================
```

### Coverage theo module

| Test File | Module được test | Số tests |
|-----------|-----------------|---------|
| `test_models.py` | Packet, Traffic, Alert, AIResult, Report | 5 |
| `test_packet.py` | Packet (chi tiết) | 1 |
| `test_traffic_analyzer.py` | TrafficAnalyzer | 5 |
| `test_detection.py` | 4 Rules + RuleEngine | 14 |
| `test_alert_manager.py` | AlertManager | 14 |
| `test_storage.py` | CSV/JSON/DB Formatter + Logger | 15 |

---

## Thiết kế quan trọng

### 1. Log song song với AI (QUAN TRỌNG NHẤT)

> **"Log là bằng chứng pháp lý, AI chỉ là công cụ hỗ trợ"**

```python
# Trong main.py:
# Bước 3: GHI LOG NGAY (không đợi AI)
self.storageLogger.logAlerts(alerts)

# Bước 4: AI chạy SONG SONG trong thread riêng
ai_future = self._ai_executor.submit(self._runAIAnalysis, alerts, stats)
```

**Lý do**: Nếu Ollama chết (RAM thiếu, model lỗi, server crash) → Log vẫn đã được ghi đầy đủ. Trong an ninh mạng, không bao giờ hy sinh tính toàn vẹn của log vì AI.

### 2. Fault Tolerance ở mọi tầng

- **RuleEngine**: 1 rule crash → các rule khác vẫn chạy
- **Logger**: 1 formatter lỗi → formatter khác vẫn ghi
- **NotificationManager**: 1 channel lỗi → channel khác vẫn gửi
- **SecurityAnalyzer**: Ollama lỗi → trả về `None`, pipeline tiếp tục

### 3. Design Patterns sử dụng

| Pattern | Nơi dùng | Lý do |
|---------|----------|-------|
| **Adapter** | `PySharkAdapter` | Tách biệt PyShark khỏi model nội bộ |
| **Strategy** | `LogFormatter`, `NotificationChannel` | Dễ thêm format/channel mới |
| **Template Method** | `Rule` (ABC) | Mọi rule đều phải có `analyze()` |
| **Factory** | `PacketParser.fromDict()`, `.fromArgs()` | Tạo Packet từ nhiều nguồn |
| **Observer/Callback** | `PacketCapture.startCapture(callback)` | Decoupling capture và processing |

### 4. Tính pháp lý của log

- CSV và JSON được flush ngay sau mỗi write → không mất data khi crash
- Mỗi alert có `timestamp` chính xác (thời điểm phát hiện)
- NDJSON cho phép audit trail: đọc từng dòng → trace lại timeline

---

*NetworkSentinelAI – Được phát triển cho môn học CSN340*
