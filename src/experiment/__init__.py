"""
Experiment Package - Automated Testing Framework for Agentic JWT

This package contains automated testing and data collection tools for
experimental validation of the Agentic JWT security framework.

Modules:
    - run_experiments: Master orchestration script
    - run_all_threats: Automated threat testing
    - langsmith_metrics: Performance data extraction from LangSmith
    - generate_latex_tables: LaTeX table generation

Usage:
    python -m experiment.run_experiments --full
"""

__version__ = "1.0.0"

from experiment.run_all_threats import ThreatTestRunner
from experiment.langsmith_metrics import LangSmithMetricsExtractor, extract_performance_metrics
from experiment.generate_latex_tables import LaTeXTableGenerator

__all__ = [
    "ThreatTestRunner",
    "LangSmithMetricsExtractor", 
    "extract_performance_metrics",
    "LaTeXTableGenerator",
]