"""PhishScan: a static analyzer for suspicious emails (.eml)."""
from .analyzer import AnalysisResult, analyze
from .parser import ParsedEmail, parse_email

__version__ = "1.1.0"
__all__ = ["parse_email", "analyze", "ParsedEmail", "AnalysisResult"]
