"""
Core module for RulePilot - contains rule types, generators, and converters.
"""

from .rule_types import Rule, SplunkRule, SentinelRule, GoogleChronicleYARALRule
from .rule_generator import RuleGenerator
from .rule_converter import (
    RuleConverter,
    generate_ir,
    generate_rule_from_ir,
    analyze_rule,
)

__all__ = [
    "Rule",
    "SplunkRule",
    "SentinelRule",
    "GoogleChronicleYARALRule",
    "RuleGenerator",
    "RuleConverter",
    "generate_ir",
    "generate_rule_from_ir",
    "analyze_rule",
]
