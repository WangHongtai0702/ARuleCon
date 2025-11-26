"""
Conversion Logger for saving intermediate outputs during rule conversion process.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from src.schemas.models import (
    OptimizationTask,
    OptimizationResult,
    OptimizationTodoList,
    CompleteOptimizationResult,
)


@dataclass
class RuleAnalysisStep:
    """Single step in rule analysis process."""

    step_name: str
    input_content: str
    output_content: str
    timestamp: str
    metadata: Dict[str, Any] = None


@dataclass
class IRGenerationStep:
    """Single step in IR generation process."""

    step_name: str
    input_rule: str
    generated_ir: str
    timestamp: str
    metadata: Dict[str, Any] = None


@dataclass
class KeywordAdjustmentStep:
    """Single step in keyword adjustment process."""

    iteration: int
    task_name: str
    original_keyword: str
    adjusted_keyword: str
    reflection_prompt: str
    reflection_response: str
    timestamp: str
    metadata: Dict[str, Any] = None


@dataclass
class RAGSearchStep:
    """Single step in RAG search process."""

    iteration: int
    task_name: str
    search_keyword: str
    search_query: str
    retrieved_documents: List[str]
    search_results_count: int
    timestamp: str
    metadata: Dict[str, Any] = None


@dataclass
class RuleOptimizationStep:
    """Single step in rule optimization process."""

    task_name: str
    original_rule: str
    optimized_rule: str
    optimization_prompt: str
    optimization_response: str
    semantic_score: float
    timestamp: str
    metadata: Dict[str, Any] = None


@dataclass
class SemanticOptimizationStep:
    """Single step in semantic optimization process."""

    step_name: str
    test_log_data: List[str]
    source_code_blocks: List[str]
    target_code_blocks: List[str]
    source_execution_context: Dict[str, Any]  # Execution context for source rule
    target_execution_context: Dict[str, Any]  # Execution context for target rule
    source_execution_results: List[bool]
    target_execution_results: List[bool]
    matches_count: int
    total_tests: int
    equivalence_score: float
    timestamp: str
    metadata: Dict[str, Any] = None


@dataclass
class ConversionProcessLog:
    """Complete log of a conversion process."""

    # Basic information
    source_rule_type: str
    target_rule_type: str
    start_time: str
    end_time: str
    total_duration_seconds: float

    # Input and final output
    original_rule: str
    final_rule: str

    # Analysis phase
    rule_analysis_steps: List[RuleAnalysisStep] = None

    # IR generation phase
    ir_generation_steps: List[IRGenerationStep] = None
    final_ir: str = None

    # Optimization phase
    todo_list: Dict[str, Any] = None
    keyword_adjustment_steps: List[KeywordAdjustmentStep] = None
    rag_search_steps: List[RAGSearchStep] = None
    rule_optimization_steps: List[RuleOptimizationStep] = None
    optimization_results: List[Dict[str, Any]] = None

    # Semantic optimization phase
    semantic_optimization_steps: List[SemanticOptimizationStep] = None

    # Summary
    total_tasks_completed: int = 0
    overall_semantic_score: float = 0.0
    success: bool = True
    error_message: str = None


class ConversionLogger:
    """Logger for saving conversion process intermediate outputs."""

    def __init__(self, result_dir: str = "result/streamlit"):
        """
        Initialize the conversion logger.

        Args:
            result_dir: Directory to save result files
        """
        self.result_dir = Path(result_dir)
        self.result_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Current conversion log
        self.current_log: Optional[ConversionProcessLog] = None

    def start_conversion(
        self, source_rule_type: str, target_rule_type: str, original_rule: str
    ) -> str:
        """
        Start logging a new conversion process.

        Args:
            source_rule_type: Source rule type (e.g., "Splunk")
            target_rule_type: Target rule type (e.g., "Microsoft Sentinel")
            original_rule: Original rule content

        Returns:
            Conversion ID for this process
        """
        start_time = datetime.now().isoformat()

        self.current_log = ConversionProcessLog(
            source_rule_type=source_rule_type,
            target_rule_type=target_rule_type,
            start_time=start_time,
            end_time="",
            total_duration_seconds=0.0,
            original_rule=original_rule,
            final_rule="",
            rule_analysis_steps=[],
            ir_generation_steps=[],
            keyword_adjustment_steps=[],
            rag_search_steps=[],
            rule_optimization_steps=[],
            optimization_results=[],
            semantic_optimization_steps=[],
        )

        self.logger.info(
            f"Started conversion logging: {source_rule_type} -> {target_rule_type}"
        )
        return f"{source_rule_type}_{target_rule_type}_{start_time.replace(':', '-')}"

    def log_rule_analysis_step(
        self,
        step_name: str,
        input_content: str,
        output_content: str,
        metadata: Dict[str, Any] = None,
    ):
        """Log a rule analysis step."""
        if not self.current_log:
            return

        step = RuleAnalysisStep(
            step_name=step_name,
            input_content=input_content,
            output_content=output_content,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {},
        )

        self.current_log.rule_analysis_steps.append(step)
        self.logger.debug(f"Logged rule analysis step: {step_name}")

    def log_ir_generation_step(
        self,
        step_name: str,
        input_rule: str,
        generated_ir: str,
        metadata: Dict[str, Any] = None,
    ):
        """Log an IR generation step."""
        if not self.current_log:
            return

        step = IRGenerationStep(
            step_name=step_name,
            input_rule=input_rule,
            generated_ir=generated_ir,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {},
        )

        self.current_log.ir_generation_steps.append(step)
        self.logger.debug(f"Logged IR generation step: {step_name}")

    def log_todo_list(self, todo_list: OptimizationTodoList):
        """Log the generated todo list."""
        if not self.current_log:
            return

        self.current_log.todo_list = todo_list.to_dict()
        self.logger.debug(f"Logged todo list with {len(todo_list.tasks)} tasks")

    def log_keyword_adjustment_step(
        self,
        iteration: int,
        task_name: str,
        original_keyword: str,
        adjusted_keyword: str,
        reflection_prompt: str,
        reflection_response: str,
        metadata: Dict[str, Any] = None,
    ):
        """Log a keyword adjustment step."""
        if not self.current_log:
            return

        step = KeywordAdjustmentStep(
            iteration=iteration,
            task_name=task_name,
            original_keyword=original_keyword,
            adjusted_keyword=adjusted_keyword,
            reflection_prompt=reflection_prompt,
            reflection_response=reflection_response,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {},
        )

        self.current_log.keyword_adjustment_steps.append(step)
        self.logger.debug(
            f"Logged keyword adjustment step: {task_name} iteration {iteration}"
        )

    def log_rag_search_step(
        self,
        iteration: int,
        task_name: str,
        search_keyword: str,
        search_query: str,
        retrieved_documents: List[str],
        metadata: Dict[str, Any] = None,
    ):
        """Log a RAG search step."""
        if not self.current_log:
            return

        step = RAGSearchStep(
            iteration=iteration,
            task_name=task_name,
            search_keyword=search_keyword,
            search_query=search_query,
            retrieved_documents=retrieved_documents,
            search_results_count=len(retrieved_documents),
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {},
        )

        self.current_log.rag_search_steps.append(step)
        self.logger.debug(f"Logged RAG search step: {task_name} iteration {iteration}")

    def log_rule_optimization_step(
        self,
        task_name: str,
        original_rule: str,
        optimized_rule: str,
        optimization_prompt: str,
        optimization_response: str,
        semantic_score: float,
        metadata: Dict[str, Any] = None,
    ):
        """Log a rule optimization step."""
        if not self.current_log:
            return

        step = RuleOptimizationStep(
            task_name=task_name,
            original_rule=original_rule,
            optimized_rule=optimized_rule,
            optimization_prompt=optimization_prompt,
            optimization_response=optimization_response,
            semantic_score=semantic_score,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {},
        )

        self.current_log.rule_optimization_steps.append(step)
        self.logger.debug(f"Logged rule optimization step: {task_name}")

    def log_rule_optimization(
        self,
        original_rule: str,
        optimized_rule: str,
        optimization_suggestions: List[str],
        equivalence_score: float,
        metadata: Dict[str, Any] = None,
    ):
        """Log rule optimization results from semantic optimization."""
        if not self.current_log:
            return

        # Create a rule optimization step for the semantic optimization
        step = RuleOptimizationStep(
            task_name="semantic_optimization",
            original_rule=original_rule,
            optimized_rule=optimized_rule,
            optimization_prompt="Semantic optimization based on LLM comparison",
            optimization_response=f"Applied {len(optimization_suggestions)} suggestions based on LLM analysis",
            semantic_score=equivalence_score,
            timestamp=datetime.now().isoformat(),
            metadata={
                **(metadata or {}),
                "optimization_suggestions": optimization_suggestions,
                "equivalence_score": equivalence_score,
                "comparison_method": "llm_comparison",
                "llm_analysis": metadata.get("llm_analysis", "") if metadata else "",
                "llm_reasoning": metadata.get("llm_reasoning", "") if metadata else "",
            },
        )

        self.current_log.rule_optimization_steps.append(step)
        self.logger.debug(
            f"Logged rule optimization with {len(optimization_suggestions)} suggestions"
        )

    def log_optimization_results(self, results: List[OptimizationResult]):
        """Log optimization results."""
        if not self.current_log:
            return

        self.current_log.optimization_results = [result.to_dict() for result in results]
        self.logger.debug(f"Logged {len(results)} optimization results")

    def log_semantic_optimization_step(
        self,
        step_name: str,
        test_log_data: List[str],
        source_code_blocks: List[str],
        target_code_blocks: List[str],
        source_execution_context: Dict[str, Any],
        target_execution_context: Dict[str, Any],
        source_execution_results: List[bool],
        target_execution_results: List[bool],
        matches_count: int,
        total_tests: int,
        equivalence_score: float,
        metadata: Dict[str, Any] = None,
    ):
        """Log a semantic optimization step."""
        if not self.current_log:
            return

        step = SemanticOptimizationStep(
            step_name=step_name,
            test_log_data=test_log_data,
            source_code_blocks=source_code_blocks,
            target_code_blocks=target_code_blocks,
            source_execution_context=source_execution_context,
            target_execution_context=target_execution_context,
            source_execution_results=source_execution_results,
            target_execution_results=target_execution_results,
            matches_count=matches_count,
            total_tests=total_tests,
            equivalence_score=equivalence_score,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {},
        )

        if self.current_log.semantic_optimization_steps is None:
            self.current_log.semantic_optimization_steps = []

        self.current_log.semantic_optimization_steps.append(step)
        self.logger.debug(f"Logged semantic optimization step: {step_name}")

    def log_final_ir(self, final_ir: str):
        """Log the final IR."""
        if not self.current_log:
            return

        self.current_log.final_ir = final_ir
        self.logger.debug("Logged final IR")

    def finish_conversion(
        self,
        final_rule: str,
        success: bool = True,
        error_message: str = None,
        total_tasks_completed: int = 0,
        overall_semantic_score: float = 0.0,
    ) -> str:
        """
        Finish the conversion process and save the log.

        Args:
            final_rule: Final converted rule
            success: Whether the conversion was successful
            error_message: Error message if conversion failed
            total_tasks_completed: Total number of tasks completed
            overall_semantic_score: Overall semantic preservation score

        Returns:
            Path to the saved log file
        """
        if not self.current_log:
            self.logger.warning("No current conversion log to finish")
            return ""

        end_time = datetime.now().isoformat()
        start_time = datetime.fromisoformat(self.current_log.start_time)
        end_time_dt = datetime.fromisoformat(end_time)
        duration = (end_time_dt - start_time).total_seconds()

        # Update final information
        self.current_log.end_time = end_time
        self.current_log.total_duration_seconds = duration
        self.current_log.final_rule = final_rule
        self.current_log.success = success
        self.current_log.error_message = error_message
        self.current_log.total_tasks_completed = total_tasks_completed
        self.current_log.overall_semantic_score = overall_semantic_score

        # Generate filename
        timestamp = self.current_log.start_time.replace(":", "-").replace(".", "-")
        filename = f"{self.current_log.source_rule_type}_to_{self.current_log.target_rule_type}_{timestamp}.json"
        filepath = self.result_dir / filename

        # Save to file
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(asdict(self.current_log), f, indent=2, ensure_ascii=False)

            self.logger.info(f"Conversion log saved to: {filepath}")
            return str(filepath)

        except Exception as e:
            self.logger.error(f"Failed to save conversion log: {e}")
            return ""

        finally:
            # Clear current log
            self.current_log = None


# Global logger instance
conversion_logger = ConversionLogger()
