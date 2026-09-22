"""Report exporters (§31): JSON, HTML, PDF."""

from .html_report import render_html
from .json_report import build_report

__all__ = ["build_report", "render_html"]
