from datetime import datetime

class AIResult:
    """
    Structures the security classification and assessment results returned by AI analyzer models.
    """
    def __init__(
        self,
        riskLevel: str,
        confidence: float,
        explanation: str,
        recommendation: str,
        timestamp: datetime
    ):
        self.riskLevel = riskLevel
        self.confidence = confidence
        self.explanation = explanation
        self.recommendation = recommendation
        self.timestamp = timestamp

    def toDictionary(self) -> dict:
        """
        Serializes the AIResult object to a Python dictionary format.
        """
        return {
            "riskLevel": self.riskLevel,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp
        }
