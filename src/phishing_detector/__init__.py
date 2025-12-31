"""Phishing detection package."""

from .analyzer import analyze_email, analyze_url
from .port_scanner import scan_ports

__all__ = ["analyze_email", "analyze_url", "scan_ports"]
