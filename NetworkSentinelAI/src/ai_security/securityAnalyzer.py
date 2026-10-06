"""
SecurityAnalyzer – AI Security Analysis
=========================================
Phân tích chuyên sâu các Alert bằng LLM cục bộ (Ollama).

Nhiệm vụ:
  1. Nhận một hoặc nhiều Alert từ RuleEngine
  2. Tổng hợp thành prompt mô tả rõ ràng tình huống bảo mật
  3. Gửi cho Ollama AI để nhận đánh giá rủi ro và khuyến nghị
  4. Parse response và tạo AIResult object

Thiết kế quan trọng:
  - KHÔNG BLOCK pipeline: nếu AI lỗi → trả về None, pipeline tiếp tục
  - Chạy trong thread riêng (threading) ở main.py để song song với Logger
  - Prompt được thiết kế cẩn thận để AI trả về dữ liệu có cấu trúc

Prompt engineering strategy:
  - Mô tả rõ context: đây là hệ thống IDS
  - Cung cấp đủ thông tin: loại tấn công, số lượng, IP
  - Yêu cầu output có cấu trúc: riskLevel + explanation + recommendation
  - Giới hạn độ dài: tránh model "nói quá nhiều"
"""

import json
import logging
import sys
import os
from datetime import datetime
from typing import List, Optional, Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.alert import Alert
from models.aiResult import AIResult
from ai_security.local_model.ollamaClient import OllamaClient

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """
    Phân tích bảo mật nâng cao bằng AI cục bộ (Ollama).

    Attributes:
        client (OllamaClient): Client giao tiếp với Ollama
        confidenceThreshold (float): Ngưỡng để chấp nhận kết quả AI
        _ai_available (bool): Cache trạng thái AI (tránh gọi isAvailable() liên tục)
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Args:
            config (dict): Config từ config.yaml, phần "security_analyzer"
                           {"model": "llama2", "threshold": 0.85}
        """
        config = config or {}
        model = config.get("model", "llama2")
        self.confidenceThreshold = config.get("threshold", 0.85)

        self.client = OllamaClient(model=model, timeout=45, max_retries=2)
        self._ai_available: Optional[bool] = None  # None = chưa check

        logger.info(f"SecurityAnalyzer khởi tạo: model={model}, threshold={self.confidenceThreshold}")

    def analyze(self, alerts: List[Alert]) -> Optional[AIResult]:
        """
        Phân tích danh sách Alert bằng AI và trả về AIResult.

        Luồng xử lý:
          1. Kiểm tra AI có khả dụng không (cache 5 phút)
          2. Tạo prompt từ alerts
          3. Gửi đến Ollama
          4. Parse response → AIResult
          5. Nếu bất kỳ bước nào lỗi → return None

        Args:
            alerts (List[Alert]): Danh sách Alert cần phân tích

        Returns:
            Optional[AIResult]: Kết quả AI, hoặc None nếu AI không khả dụng
        """
        if not alerts:
            return None

        # Kiểm tra AI availability (lần đầu check thật, sau cache)
        if self._ai_available is None:
            self._ai_available = self.client.isAvailable()
            if not self._ai_available:
                logger.warning("AI không khả dụng. SecurityAnalyzer sẽ bỏ qua cho session này.")

        if not self._ai_available:
            return None

        # Tạo prompt
        prompt = self._buildPrompt(alerts)

        # Gọi AI
        logger.info(f"Gửi {len(alerts)} alert(s) đến AI để phân tích...")
        raw_response = self.client.generate(prompt)

        if not raw_response:
            logger.warning("AI không trả về kết quả. Bỏ qua AI analysis.")
            return None

        # Parse response thành AIResult
        return self._parseResponse(raw_response)

    def analyzeOne(self, alert: Alert) -> Optional[AIResult]:
        """
        Phân tích một Alert đơn lẻ.

        Args:
            alert (Alert): Alert cần phân tích

        Returns:
            Optional[AIResult]: Kết quả AI
        """
        return self.analyze([alert])

    def _buildPrompt(self, alerts: List[Alert]) -> str:
        """
        Xây dựng prompt có cấu trúc để gửi cho AI.

        Prompt engineering:
          - Thiết lập role: AI là chuyên gia bảo mật mạng
          - Cung cấp context: thông tin chi tiết về các alert
          - Yêu cầu output JSON có cấu trúc
          - Hướng dẫn rõ: không nói lan man

        Args:
            alerts (List[Alert]): Danh sách Alert

        Returns:
            str: Prompt đầy đủ để gửi cho LLM
        """
        # Tóm tắt thông tin alerts
        alert_summaries = []
        for i, alert in enumerate(alerts[:10], 1):     # Giới hạn 10 alert để tránh quá dài
            alert_summaries.append(
                f"{i}. [{alert.severity.upper()}] {alert.attackType} "
                f"from {alert.sourceIp} → {alert.destinationIp} "
                f"(confidence: {alert.confidence:.2f}) - {alert.description[:200]}"
            )

        alert_text = "\n".join(alert_summaries)

        # Thống kê
        attack_types = list({a.attackType for a in alerts})
        source_ips = list({a.sourceIp for a in alerts})
        critical_count = sum(1 for a in alerts if a.severity == "critical")

        prompt = f"""You are a network security expert analyzing alerts from an IDS (Intrusion Detection System).

ALERT SUMMARY:
- Total alerts: {len(alerts)}
- Critical alerts: {critical_count}
- Attack types detected: {', '.join(attack_types)}
- Source IPs involved: {', '.join(source_ips[:5])}

ALERT DETAILS:
{alert_text}

Based on these security alerts, provide a structured analysis in the following JSON format ONLY (no other text):
{{
  "riskLevel": "<critical|high|medium|low>",
  "confidence": <0.0-1.0>,
  "explanation": "<Brief explanation of the threat in 2-3 sentences>",
  "recommendation": "<Specific actionable recommendations in 2-3 sentences>"
}}

Respond with ONLY the JSON object, no additional text."""

        return prompt

    def _parseResponse(self, raw_response: str) -> Optional[AIResult]:
        """
        Parse text response từ AI thành AIResult object.

        Xử lý các trường hợp:
          1. AI trả về JSON thuần → parse trực tiếp
          2. AI trả về JSON trong markdown code block → extract JSON
          3. AI không theo format → dùng heuristic để extract thông tin

        Args:
            raw_response (str): Text response thô từ AI

        Returns:
            Optional[AIResult]: AIResult object, hoặc None nếu không parse được
        """
        # Thử parse JSON trực tiếp
        parsed = self._tryParseJSON(raw_response)

        if not parsed:
            # Thử tìm JSON trong markdown code block ```json ... ```
            import re
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', raw_response)
            if json_match:
                parsed = self._tryParseJSON(json_match.group(1))

        if not parsed:
            # Fallback: dùng heuristic để xác định risk level từ text
            parsed = self._heuristicParse(raw_response)

        if not parsed:
            logger.warning("Không thể parse AI response")
            return None

        # Validate và build AIResult
        try:
            risk_level = parsed.get("riskLevel", "unknown").lower()
            if risk_level not in ("critical", "high", "medium", "low"):
                risk_level = "unknown"

            confidence = float(parsed.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))     # Clamp 0-1

            return AIResult(
                riskLevel=risk_level,
                confidence=round(confidence, 4),
                explanation=str(parsed.get("explanation", "Không có giải thích")),
                recommendation=str(parsed.get("recommendation", "Không có khuyến nghị")),
                timestamp=datetime.now()
            )
        except Exception as e:
            logger.error(f"Lỗi tạo AIResult: {e}")
            return None

    def _tryParseJSON(self, text: str) -> Optional[Dict]:
        """Thử parse text thành dict JSON."""
        try:
            text = text.strip()
            # Tìm { } bao ngoài
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    def _heuristicParse(self, text: str) -> Optional[Dict]:
        """
        Phân tích heuristic khi AI không trả về JSON đúng format.
        Tìm các từ khóa để xác định risk level.
        """
        text_lower = text.lower()
        risk_level = "medium"

        if any(word in text_lower for word in ["critical", "severe", "immediate", "emergency"]):
            risk_level = "critical"
        elif any(word in text_lower for word in ["high", "serious", "significant", "dangerous"]):
            risk_level = "high"
        elif any(word in text_lower for word in ["low", "minor", "minimal", "benign"]):
            risk_level = "low"

        return {
            "riskLevel": risk_level,
            "confidence": 0.5,
            "explanation": text[:300] if len(text) > 0 else "Không có giải thích",
            "recommendation": "Xem xét thủ công các alert và kiểm tra log chi tiết."
        }
