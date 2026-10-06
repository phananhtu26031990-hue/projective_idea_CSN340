"""
OllamaClient – Giao tiếp với Ollama Local AI Server
=====================================================
Ollama là server chạy LLM (Large Language Model) cục bộ trên máy tính.
Không cần internet, không gửi dữ liệu ra ngoài → phù hợp cho bảo mật.

Cách cài đặt Ollama:
  1. Tải: https://ollama.ai/
  2. Cài model: ollama pull llama2
  3. Server tự chạy tại: http://localhost:11434

API Ollama:
  POST http://localhost:11434/api/generate
  Body: {"model": "llama2", "prompt": "...", "stream": false}
  Response: {"response": "...", "done": true, ...}

Thiết kế defensive:
  - Timeout ngắn (mặc định 30s) để không block pipeline
  - Retry tối đa 2 lần
  - Trả về None thay vì raise exception
"""

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger(__name__)

OLLAMA_API_URL = "http://localhost:11434/api/generate"


class OllamaClient:
    """
    HTTP client để giao tiếp với Ollama API.

    Attributes:
        model (str): Tên model AI sử dụng (ví dụ: "llama2", "mistral")
        timeout (int): Thời gian chờ tối đa mỗi request (giây)
        maxRetries (int): Số lần thử lại nếu request thất bại
    """

    def __init__(
        self,
        model: str = "llama2",
        timeout: int = 30,
        max_retries: int = 2,
        base_url: str = OLLAMA_API_URL
    ):
        """
        Args:
            model (str): Tên model Ollama
            timeout (int): Timeout HTTP request (giây)
            max_retries (int): Số lần retry khi lỗi
            base_url (str): URL Ollama API endpoint
        """
        self.model = model
        self.timeout = timeout
        self.maxRetries = max_retries
        self.base_url = base_url

    def generate(self, prompt: str) -> Optional[str]:
        """
        Gửi prompt đến Ollama và nhận kết quả text.

        Xử lý lỗi:
          - ConnectionRefusedError: Ollama chưa chạy
          - TimeoutError: Model quá chậm (RAM thiếu?)
          - JSONDecodeError: Response không đúng format
          → Tất cả đều return None, không raise exception

        Args:
            prompt (str): Câu hỏi/lệnh gửi cho AI

        Returns:
            Optional[str]: Text phản hồi từ AI, hoặc None nếu lỗi
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False             # Đợi toàn bộ response, không stream từng token
        }
        data = json.dumps(payload).encode("utf-8")

        for attempt in range(1, self.maxRetries + 1):
            try:
                request = urllib.request.Request(
                    url=self.base_url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )

                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    response_data = json.loads(response.read().decode("utf-8"))
                    ai_text = response_data.get("response", "").strip()

                    if ai_text:
                        logger.debug(f"Ollama ({self.model}): Response nhận được ({len(ai_text)} chars)")
                        return ai_text
                    else:
                        logger.warning(f"Ollama: Response rỗng (attempt {attempt})")

            except urllib.error.URLError as e:
                # Ollama chưa khởi động hoặc không thể kết nối
                if attempt == self.maxRetries:
                    logger.warning(f"Ollama không khả dụng: {e}. Bỏ qua AI analysis.")
                else:
                    logger.debug(f"Ollama connection error (attempt {attempt}): {e}. Thử lại...")
                    time.sleep(1)                   # Đợi 1 giây trước khi retry

            except TimeoutError:
                logger.warning(f"Ollama timeout sau {self.timeout}s (attempt {attempt})")
                if attempt < self.maxRetries:
                    time.sleep(2)

            except json.JSONDecodeError as e:
                logger.error(f"Ollama: Response không hợp lệ JSON: {e}")
                break                               # JSON error → không cần retry

            except Exception as e:
                logger.error(f"Ollama: Lỗi không xác định (attempt {attempt}): {e}")
                break

        return None

    def isAvailable(self) -> bool:
        """
        Kiểm tra Ollama server có đang chạy và model có sẵn sàng không.

        Dùng trước khi chạy AI analysis để quyết định có thử không.

        Returns:
            bool: True nếu Ollama đang chạy và model khả dụng
        """
        try:
            test_url = self.base_url.replace("/api/generate", "/api/tags")
            with urllib.request.urlopen(test_url, timeout=3) as response:
                data = json.loads(response.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                # Kiểm tra model cần dùng có trong danh sách không
                available = any(self.model in m for m in models)
                if not available:
                    logger.warning(
                        f"Model '{self.model}' không có sẵn trong Ollama. "
                        f"Models hiện có: {models}. "
                        f"Chạy: ollama pull {self.model}"
                    )
                return available
        except Exception:
            return False
