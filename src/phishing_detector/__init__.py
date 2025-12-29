"""Phishing detection package."""

from .analyzer import analyze_email, analyze_url

__all__ = ["analyze_email", "analyze_url"]
