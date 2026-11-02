"""phishing_detector: defensive, offline phishing-signal scoring."""
from .detector import Result, analyse, risk_level

__all__ = ["Result", "analyse", "risk_level"]
__version__ = "0.1.0"
