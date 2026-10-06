# 🎓 Lộ Trình Học Tập & Phân Tích Code: NetworkSentinelAI

Dự án này được thiết kế theo kiến trúc **Layered Architecture (Kiến trúc phân tầng)** và áp dụng nhiều **Design Patterns (Mẫu thiết kế)**. Vì code khá đồ sộ (hơn 10 module, 30+ files), việc đọc code từ trên xuống dưới ở `main.py` sẽ làm bạn bị ngợp.

Dưới đây là **lộ trình chuẩn 5 giai đoạn** để bạn "giải phẫu" và hiểu sâu toàn bộ hệ thống này.

---

## 🎯 Giai Đoạn 0: Kiến thức nền tảng cần chuẩn bị
Trước khi đọc code, bạn cần chắc chắn mình nắm vững:
1. **Mạng máy tính cơ bản**: Hiểu về TCP (SYN, ACK), UDP, ICMP, Port là gì.
2. **Lập trình Hướng đối tượng (OOP) Python**: Hiểu về `Class`, `Inheritance` (Kế thừa), `Interface` (Abstract Base Class - ABC trong Python).
3. **Đa luồng (Threading)**: Hiểu cơ bản về việc chạy 2 việc cùng lúc (chạy song song AI, Notification).

---

## 🗺️ Giai Đoạn 1: Hiểu Dữ Liệu Lõi (Data Models)
*Đừng quan tâm dữ liệu đến từ đâu, hãy xem hệ thống định nghĩa "gói tin", "cảnh báo" là gì.*

📍 **Files cần đọc:** Thư mục `src/models/`
1. **`packet.py`**: Đây là linh hồn của hệ thống. Xem cách class `Packet` lưu trữ: IP nguồn, IP đích, port, protocol (TCP/UDP). Hãy chú ý các hàm tiện ích như `isTCP()`, `isSYN()`.
2. **`traffic.py`**: Xem cách hệ thống "gom" nhiều `Packet` lại thành một "cửa sổ thời gian" (Traffic window) bằng hàm `addPacket()`.
3. **`alert.py`**: Xem một cảnh báo bảo mật được cấu tạo từ những trường nào (Severity, Confidence, RuleName).

💡 **Bài tập hiểu bài**: Thử viết 1 script nhỏ (bên ngoài), khởi tạo thủ công 5 đối tượng `Packet`, nhét vào `Traffic` và gọi `traffic.getStatistics()`.

---

## 🚦 Giai Đoạn 2: Luồng thu thập & Tiền xử lý
*Sau khi biết gói tin trông như thế nào, ta xem cách phần mềm "bắt" nó từ card mạng.*

📍 **Files cần đọc:** Thư mục `src/capture/` và `src/trafficProcessing/`
1. **`pysharkAdapter.py`**: Đọc để hiểu mẫu thiết kế **Adapter Pattern**. PyShark trả về dữ liệu rất phức tạp, Adapter này có nhiệm vụ "rút gọn" dữ liệu đó và biến nó thành đối tượng `Packet` (mà ta đã học ở Giai đoạn 1).
2. **`packetCapture.py`**: Xem cách hàm `startCapture` dùng callback function. Khi có gói tin mới, nó đẩy gói tin đi đâu?
3. **`trafficAnalyzer.py`**: **RẤT QUAN TRỌNG**. Đọc logic hàm `processPacket()`. Hãy hiểu cơ chế **"Sliding Window"** (Cửa sổ trượt): Khi gói tin đến, làm sao nó biết đã quá 10 giây để đóng cửa sổ cũ và mở cửa sổ mới?

---

## 🧠 Giai Đoạn 3: Bộ não phát hiện tấn công (Detection)
*Đây là phần quan trọng nhất của một hệ thống IDS.*

📍 **Files cần đọc:** Thư mục `src/detection/`
1. **`ruleInterface.py`**: Đọc trước tiên! Đây là bộ khung ép buộc tất cả các Luật (Rule) đều phải có hàm `analyze(traffic)`.
2. **`rules/synFloodRule.py` & `portScanRule.py`**: Chọn đọc 2 luật này. Hãy xem hàm `analyze()` lặp qua các gói tin trong `Traffic` như thế nào để đếm số gói SYN hoặc đếm số Port khác nhau. Từ đó quyết định tạo ra `Alert`.
3. **`ruleEngine.py`**: Xem cách "Người quản lý" gộp tất cả các Rules lại. Chú ý cấu trúc `try...except` bao bọc lấy từng Rule. Nếu 1 Rule bị lỗi code, các Rule khác vẫn chạy bình thường.

---

## 💾 Giai Đoạn 4: Hậu kỳ (Lưu trữ, Cảnh báo & AI)
*Sau khi Rule phát hiện ra `Alert`, chúng đi đâu tiếp?*

📍 **Files cần đọc:** Thư mục `src/storage/` và `src/notification/`
1. **Strategy Pattern trong Storage**: 
   - Đọc `logFormatterInterface.py` (cái khung).
   - Đọc `csvFormatter.py` và `jsonFormatter.py` (cách triển khai). 
   - Đọc `logger.py`: Xem cách Logger gọi hàm `write()` cho TẤT CẢ các formatter cùng lúc.
2. **`notificationManager.py`**: Xem cách hệ thống lọc `min_severity` (chỉ những Alert từ `high` trở lên mới được gửi đi).
3. **`ai_security/securityAnalyzer.py`**: Đọc để biết cách hệ thống lấy chuỗi cảnh báo đem ráp vào Text Prompt và gửi cho AI (Ollama).

---

## 🎭 Giai Đoạn 5: Người Nhạc Trưởng (`main.py`)
*Mảnh ghép cuối cùng. Khi đã hiểu từng bộ phận, hãy xem chúng lắp ráp với nhau.*

📍 **File cần đọc:** `src/main.py`
1. **Hàm `__init__`**: Xem thứ tự khởi tạo. Nó đọc `ConfigLoader` đầu tiên, sau đó truyền cấu hình vào để tạo RuleEngine, Logger, Notification.
2. **Hàm `_processTrafficWindow()`**: Đây là trái tim của Pipeline. Hãy đọc từng bước theo đúng thứ tự:
   - Bước 1: Gửi Traffic cho RuleEngine để lấy Alert.
   - Bước 2: Lưu Alert vào AlertManager.
   - Bước 3: **GHI LOG NGAY LẬP TỨC** (bằng Logger).
   - Bước 4: Chạy AI (Submit vào ThreadPool).
   - Bước 5: Chạy Notification (Submit vào ThreadPool).
3. Tại sao AI và Notification phải chạy qua `ThreadPoolExecutor`? Vì gửi email và gọi AI rất chậm, nếu chạy tuần tự, card mạng sẽ làm rơi gói tin mới. Việc đẩy ra Thread riêng giúp luồng chính luôn rảnh tay để bắt gói tin tiếp theo.

---

## 🌟 Tổng hợp Design Patterns (Câu hỏi bảo vệ đồ án thường gặp)

Nếu giáo viên hỏi bạn đã dùng những kỹ thuật lập trình nâng cao nào, hãy chỉ vào các file này:

1. **Adapter Pattern** (`pysharkAdapter.py`): Giúp đổi thư viện bắt gói tin (từ PyShark sang Scapy) mà không ảnh hưởng toàn bộ project.
2. **Strategy Pattern** (`Logger` & `Formatters`): Giúp hệ thống ghi log ra nhiều định dạng cùng lúc, thích thêm format nào thì tạo file mới, không cần sửa code cũ.
3. **Template/Interface** (`RuleInterface` & `NotificationChannel`): Đảm bảo tính mở rộng. Muốn thêm một thuật toán phát hiện tấn công mới? Chỉ cần viết 1 file kế thừa `RuleInterface`, hệ thống tự động nhận. Không cần sửa vào lõi.
4. **Observer Pattern (Callback)**: Trong `packetCapture.py`, khi có gói tin mới nó sẽ "gọi ngược" (callback) về `handlePacket` của `main.py`.

---

**💡 Lời khuyên cuối:** Hãy mở 2 cửa sổ, một bên là sơ đồ Kiến trúc (trong file README.md), một bên là file code. Bạn có thể chèn các câu lệnh `print()` vào từng hàm ở các file trên, sau đó chạy lệnh `python src/main.py --dry-run` để quan sát dòng chảy dữ liệu trên màn hình console!
