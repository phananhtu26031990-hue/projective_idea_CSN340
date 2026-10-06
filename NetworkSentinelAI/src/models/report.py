from datetime import datetime
from typing import List, Optional
from .alert import Alert
from .aiResult import AIResult

class Report:
    """
    Compiles captured alerts, AI analysis results, and traffic statistics into a single structured report.
    """
    def __init__(
        self,
        id: str,
        timestamp: datetime,
        alerts: List[Alert],
        aiResult: Optional[AIResult],
        statistics: dict,
        title: str = "Network Sentinel Security Incident Report",
        summary: str = ""
    ):
        self.id = id
        self.timestamp = timestamp
        self.alerts = alerts
        self.aiResult = aiResult
        self.statistics = statistics
        self.title = title
        self.summary = summary

    def toDictionary(self) -> dict:
        """
        Serializes the Report object to a nested dictionary.
        Handles nested objects (Alerts, AIResult) using their respective serialization methods.
        """
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "alerts": [alert.toDictionary() for alert in self.alerts],
            "aiResult": self.aiResult.toDictionary() if self.aiResult else None,
            "statistics": self.statistics,
            "title": self.title,
            "summary": self.summary
        }
