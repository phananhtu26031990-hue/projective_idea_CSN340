"""
Layer 6 – AI Security Layer
==============================
Phân tích chuyên sâu các Alert bằng mô hình AI cục bộ (Ollama).

Kiến trúc:
  SecurityAnalyzer ──── OllamaClient ──── Ollama Server (local)
                                              │
                                          LLM Model
                                          (llama2, mistral...)

Triết lý thiết kế (từ task.txt):
  "Nếu AI lỗi → Ollama chết, Model lỗi, RAM thiếu"
  → SecurityAnalyzer KHÔNG ĐƯỢC làm crash hệ thống chính
  → Tất cả lỗi AI phải được xử lý graceful
  → Trả về None nếu AI không khả dụng → pipeline tiếp tục bình thường
  → Log là bằng chứng, AI chỉ là công cụ hỗ trợ phân tích thêm
"""

from .securityAnalyzer import SecurityAnalyzer

__all__ = ["SecurityAnalyzer"]
