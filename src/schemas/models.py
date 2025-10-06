"""
Data models and schemas for RulePilot.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class RuleStep:
    """Represents a single step in a security rule."""

    action: str
    params: str
    explanation: str


@dataclass
class IntermediateRepresentation:
    """Intermediate Representation (IR) for security rules."""

    rule_name: str
    description: str
    data_source: str
    event_type: str
    steps: List[RuleStep]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "rule_name": self.rule_name,
            "description": self.description,
            "data_source": self.data_source,
            "event_type": self.event_type,
            "steps": [
                {
                    "action": step.action,
                    "params": step.params,
                    "explanation": step.explanation,
                }
                for step in self.steps
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntermediateRepresentation":
        """Create from dictionary format."""
        steps = [
            RuleStep(
                action=step_data["action"],
                params=step_data["params"],
                explanation=step_data["explanation"],
            )
            for step_data in data.get("steps", [])
        ]

        return cls(
            rule_name=data.get("rule_name", ""),
            description=data.get("description", ""),
            data_source=data.get("data_source", ""),
            event_type=data.get("event_type", ""),
            steps=steps,
        )


@dataclass
class ConversionResult:
    """Result of a rule conversion operation."""

    success: bool
    converted_rule: str
    error_message: Optional[str] = None
    source_type: Optional[str] = None
    target_type: Optional[str] = None
    ir_data: Optional[Dict[str, Any]] = None


@dataclass
class RuleAnalysis:
    """Analysis result of a security rule."""

    rule_type: str
    components: List[str]
    logic_summary: str
    data_sources: List[str]
    detection_criteria: List[str]
    recommendations: List[str]


@dataclass
class OptimizationTask:
    """Represents a single optimization task."""

    task_name: str
    description: str
    search_keyword: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "task_name": self.task_name,
            "description": self.description,
            "search_keyword": self.search_keyword,
        }

    def to_str(self) -> str:
        """Convert to string format."""
        return f"Task Name: {self.task_name}\nDescription: {self.description}\nSearch Keyword: {self.search_keyword}"


@dataclass
class OptimizationResult:
    """Result of completing a single optimization task."""

    task_name: str
    original_rule: str
    optimized_rule: str
    search_keyword_used: str
    retrieved_context: List[str]
    optimization_explanation: str
    semantic_preservation_score: float  # 0-1 score for semantic preservation

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "task_name": self.task_name,
            "original_rule": self.original_rule,
            "optimized_rule": self.optimized_rule,
            "search_keyword_used": self.search_keyword_used,
            "retrieved_context": self.retrieved_context,
            "optimization_explanation": self.optimization_explanation,
            "semantic_preservation_score": self.semantic_preservation_score,
        }


@dataclass
class OptimizationTodoList:
    """Complete optimization todo list for a rule."""

    rule_type: str
    total_tasks: int
    tasks: List[OptimizationTask]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "rule_type": self.rule_type,
            "total_tasks": self.total_tasks,
            "tasks": [task.to_dict() for task in self.tasks],
        }


@dataclass
class CompleteOptimizationResult:
    """Complete result of the entire optimization process."""

    rule_type: str
    original_rule: str
    final_optimized_rule: str
    total_tasks_completed: int
    task_results: List[OptimizationResult]
    overall_semantic_preservation_score: float
    optimization_summary: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "rule_type": self.rule_type,
            "original_rule": self.original_rule,
            "final_optimized_rule": self.final_optimized_rule,
            "total_tasks_completed": self.total_tasks_completed,
            "task_results": [result.to_dict() for result in self.task_results],
            "overall_semantic_preservation_score": self.overall_semantic_preservation_score,
            "optimization_summary": self.optimization_summary,
        }
