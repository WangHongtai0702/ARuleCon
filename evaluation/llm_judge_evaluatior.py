"""
LLM as a Judge evaluation for rule conversion results.

This module implements LLM-based evaluation to assess semantic similarity between
source and target rules across six key dimensions.
"""

import json
import os
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import pandas as pd

from dotenv import load_dotenv
from tqdm import tqdm


@dataclass
class SemanticDimensionScore:
    """Score for a single semantic dimension."""

    dimension: str
    score: float
    reasoning: str
    details: str


@dataclass
class LLMJudgeResult:
    """Result of LLM judge evaluation for a single rule."""

    source_rule_type: str
    target_rule_type: str
    rule_name: str

    # Source and target rules
    source_rule: str
    direct_converted_rule: str
    syntax_optimized_rule: str
    semantic_optimized_rule: str

    # Evaluation stages
    direct_conversion_scores: Dict[str, SemanticDimensionScore]
    syntax_optimization_scores: Dict[str, SemanticDimensionScore]
    semantic_optimization_scores: Dict[str, SemanticDimensionScore]

    # Overall scores
    direct_conversion_overall: float
    syntax_optimization_overall: float
    semantic_optimization_overall: float

    # Metadata
    file_path: str
    evaluation_timestamp: str
    llm_model: str


class LLMJudgeEvaluator:
    """Evaluator for rule conversion using LLM as a judge."""

    # Six semantic dimensions for evaluation
    SEMANTIC_DIMENSIONS = {
        "SF1": "事件范围 & 字段映射",
        "SF2": "谓词 & 布尔逻辑",
        "SF3": "时间窗口",
        "SF4": "聚合 & 阈值",
        "SF5": "关联/连接",
        "SF6": "告警触发 & 输出",
    }

    def __init__(self, model: str = "gpt-4o-mini", api_key: str = None):
        """Initialize the LLM judge evaluator."""
        # Load environment variables from .env file
        load_dotenv()

        self.model = model
        self.logger = logging.getLogger(__name__)

        # Initialize OpenAI client
        try:
            from openai import OpenAI

            if api_key is None:
                api_key = os.getenv("OPENAI_API_KEY")

            if not api_key:
                raise ValueError(
                    "OpenAI API key not found. Please set it in one of the following ways:\n"
                    "1. Pass api_key parameter to LLMJudgeEvaluator()\n"
                    "2. Set OPENAI_API_KEY in .env file\n"
                    "3. Set OPENAI_API_KEY environment variable"
                )

            self.client = OpenAI(api_key=api_key)
            self.logger.info(f"LLM Judge evaluator initialized with model: {model}")

        except ImportError:
            self.logger.error(
                "OpenAI library not available. Please install: pip install openai"
            )
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize OpenAI client: {e}")
            raise

    def load_conversion_results(self, result_dir: str = "result") -> List[Dict]:
        """
        Load all conversion results from the result directory.

        Args:
            result_dir: Directory containing conversion results

        Returns:
            List of conversion result dictionaries
        """
        results = []
        result_path = Path(result_dir)

        if not result_path.exists():
            self.logger.error(f"Result directory {result_dir} does not exist")
            return results

        # Walk through all subdirectories
        for file_path in result_path.rglob("*.json"):
            # Skip summary files
            if "SUMMARY" in file_path.name:
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Extract file metadata
                file_info = {
                    "file_path": str(file_path),
                    "file_name": file_path.name,
                    "source_type": file_path.parent.parent.name,
                    "target_type": file_path.parent.name,
                    "data": data,
                }

                results.append(file_info)
                self.logger.debug(f"Loaded result from {file_path}")

            except Exception as e:
                self.logger.warning(f"Failed to load {file_path}: {e}")

        self.logger.info(f"Loaded {len(results)} conversion results")
        return results

    def extract_rule_stages(self, data: Dict) -> Dict[str, str]:
        """
        Extract rules from different conversion stages.

        Args:
            data: Conversion result data

        Returns:
            Dictionary with rules from different stages
        """
        stages = {}

        # Extract source rule
        source_rule = data.get("source_rule", "")
        if isinstance(source_rule, dict):
            stages["source_rule"] = (
                source_rule.get("rule_content", "")
                or source_rule.get("search_query", "")
                or str(source_rule)
            )
        else:
            stages["source_rule"] = str(source_rule) if source_rule else ""

        # Extract direct conversion
        direct_conversion = data.get("direct_conversion", {})
        stages["direct_converted_rule"] = direct_conversion.get("converted_rule", "")

        # Extract syntax optimization
        syntax_optimization = data.get("syntax_optimization", {})
        stages["syntax_optimized_rule"] = syntax_optimization.get("optimized_rule", "")

        # Extract semantic optimization
        semantic_optimization = data.get("semantic_optimization", {})
        stages["semantic_optimized_rule"] = semantic_optimization.get(
            "optimized_rule", ""
        )

        return stages

    def build_evaluation_prompt(
        self, source_rule: str, target_rule: str, source_type: str, target_type: str
    ) -> str:
        """
        Build the evaluation prompt for LLM judge.

        Args:
            source_rule: Source rule content
            target_rule: Target rule content
            source_type: Source SIEM type
            target_type: Target SIEM type

        Returns:
            Formatted evaluation prompt
        """
        return f"""You are a professional cybersecurity rule analysis expert who needs to evaluate the semantic similarity between two SIEM rules.

**CRITICAL INSTRUCTION**: You must be EXTREMELY STRICT and CRITICAL in your evaluation. Most rules should NOT receive perfect scores. Look for differences, inconsistencies, and potential issues. Only give high scores (8-10) when rules are truly identical or nearly perfect.

## Task Background
- Source rule type: {source_type}
- Target rule type: {target_type}
- Evaluation objective: Ensure that rule conversion maintains the same detection logic and semantics

**EVALUATION PHILOSOPHY**: 
- Assume rules are DIFFERENT until proven identical
- Look for subtle differences that could impact detection
- Consider platform-specific nuances and limitations
- Be skeptical of apparent similarities

## Source Rule
```
{source_rule}
```

## Target Rule
```
{target_rule}
```

## Evaluation Dimensions
Please evaluate the semantic similarity between the two rules across the following six dimensions, giving a score of 0-10 for each dimension:

### SF1: Event Scope & Field Mapping (STRICT)
- **CRITICAL**: Check if rules target EXACTLY the same log sources/tables
- **CRITICAL**: Verify field mappings are semantically identical (not just similar)
- **DEDUCT POINTS** for: Different data sources, field name differences, missing fields
- **DEDUCT POINTS** for: Platform-specific field variations that could affect detection

### SF2: Predicates & Boolean Logic (STRICT)
- **CRITICAL**: Verify filtering conditions are EXACTLY equivalent
- **CRITICAL**: Ensure boolean logic (AND, OR, NOT) is identical
- **DEDUCT POINTS** for: Different operators, missing conditions, extra conditions
- **DEDUCT POINTS** for: Logical precedence differences that could change results

### SF3: Time Window (STRICT)
- **CRITICAL**: Time windows must be EXACTLY the same (e.g., 3m = 3m, not 3m ≈ 5m)
- **CRITICAL**: Time-based aggregation logic must be identical
- **DEDUCT POINTS** for: Any time window differences, even minor ones
- **DEDUCT POINTS** for: Different sliding vs fixed window implementations

### SF4: Aggregation & Thresholds (STRICT)
- **CRITICAL**: Statistical functions must be identical (count vs dcount vs sum)
- **CRITICAL**: Threshold values must be EXACTLY the same
- **DEDUCT POINTS** for: Different aggregation methods, different thresholds
- **DEDUCT POINTS** for: Missing aggregation logic or threshold conditions

### SF5: Correlation/Joins (STRICT)
- **CRITICAL**: Join keys must be EXACTLY the same
- **CRITICAL**: Time constraints for correlations must be identical
- **DEDUCT POINTS** for: Different join fields, missing correlations
- **DEDUCT POINTS** for: Different correlation time windows or logic

### SF6: Alert Triggering & Output (STRICT)
- **CRITICAL**: Trigger conditions must be EXACTLY equivalent
- **CRITICAL**: Output format and content must be identical
- **DEDUCT POINTS** for: Different alert severities, different output fields
- **DEDUCT POINTS** for: Missing alert metadata or different notification logic

## Scoring Criteria (STRICT EVALUATION)
**CRITICAL**: You must be extremely strict and critical in your evaluation. Do not give high scores unless rules are truly identical or nearly perfect.

- **10 points**: PERFECT MATCH - Rules are semantically identical, all logic, fields, thresholds, and outputs match exactly
- **8-9 points**: EXCELLENT - Very minor differences that don't affect core detection logic (e.g., slight wording changes)
- **6-7 points**: GOOD - Some differences but core detection logic preserved (e.g., different field names but same meaning)
- **4-5 points**: FAIR - Significant differences but basic functionality maintained (e.g., different thresholds or time windows)
- **2-3 points**: POOR - Major differences that could affect detection effectiveness (e.g., missing key conditions)
- **0-1 points**: FAIL - Rules are fundamentally different or missing critical components

**STRICT GUIDELINES**:
- If ANY field mapping is different, deduct points
- If ANY threshold or time window differs, deduct points  
- If ANY boolean logic differs, deduct points
- If ANY aggregation method differs, deduct points
- If ANY correlation logic differs, deduct points
- If ANY alert output differs, deduct points
- Default to lower scores when in doubt

## Output Format
Please strictly follow the JSON format below for evaluation results:

```json
{{
    "SF1": {{
        "score": <score from 0-10>,
        "reasoning": "<detailed evaluation reasoning>",
        "details": "<specific difference analysis>"
    }},
    "SF2": {{
        "score": <score from 0-10>,
        "reasoning": "<detailed evaluation reasoning>",
        "details": "<specific difference analysis>"
    }},
    "SF3": {{
        "score": <score from 0-10>,
        "reasoning": "<detailed evaluation reasoning>",
        "details": "<specific difference analysis>"
    }},
    "SF4": {{
        "score": <score from 0-10>,
        "reasoning": "<detailed evaluation reasoning>",
        "details": "<specific difference analysis>"
    }},
    "SF5": {{
        "score": <score from 0-10>,
        "reasoning": "<detailed evaluation reasoning>",
        "details": "<specific difference analysis>"
    }},
    "SF6": {{
        "score": <score from 0-10>,
        "reasoning": "<detailed evaluation reasoning>",
        "details": "<specific difference analysis>"
    }}
}}
```

**FINAL REMINDER**: 
- Be EXTREMELY CRITICAL and STRICT in your evaluation
- Most rules should receive scores between 4-7, not 8-10
- Only give perfect scores (9-10) for truly identical rules
- Look for subtle differences that could impact detection effectiveness
- Consider platform-specific limitations and differences
- When in doubt, choose the LOWER score

Please carefully analyze both rules with extreme scrutiny to ensure accurate and strict evaluation."""

    def call_llm_for_evaluation(self, prompt: str) -> Dict[str, Any]:
        """
        Call LLM for evaluation.

        Args:
            prompt: Evaluation prompt

        Returns:
            LLM response as dictionary
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a professional cybersecurity rule analysis expert who specializes in evaluating semantic similarity between SIEM rules. You must be EXTREMELY STRICT and CRITICAL in your evaluation. Most rules should NOT receive perfect scores. Look for differences, inconsistencies, and potential issues. Only give high scores (8-10) when rules are truly identical or nearly perfect. Default to lower scores when in doubt. Please strictly follow the required JSON format for evaluation results.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,  # Low temperature for consistent evaluation
                max_tokens=2000,
            )

            content = response.choices[0].message.content.strip()

            # Try to extract JSON from the response
            json_match = re.search(r"```json\s*(\{.*?\})\s*```", content, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find JSON without code blocks
                json_match = re.search(r"(\{.*\})", content, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    raise ValueError("No JSON found in LLM response")

            result = json.loads(json_str)

            # Validate the result structure
            for dimension in self.SEMANTIC_DIMENSIONS.keys():
                if dimension not in result:
                    raise ValueError(f"Missing dimension {dimension} in LLM response")

                dim_result = result[dimension]
                if not all(
                    key in dim_result for key in ["score", "reasoning", "details"]
                ):
                    raise ValueError(f"Invalid structure for dimension {dimension}")

                # Validate score range
                score = dim_result["score"]
                if not isinstance(score, (int, float)) or not (0 <= score <= 10):
                    raise ValueError(f"Invalid score {score} for dimension {dimension}")

            return result

        except Exception as e:
            self.logger.error(f"LLM evaluation failed: {e}")
            # Return default scores if LLM fails
            return {
                dimension: {
                    "score": 0.0,
                    "reasoning": f"LLM evaluation failed: {str(e)}",
                    "details": "Unable to evaluate due to LLM error",
                }
                for dimension in self.SEMANTIC_DIMENSIONS.keys()
            }

    def evaluate_rule_pair(
        self, source_rule: str, target_rule: str, source_type: str, target_type: str
    ) -> Dict[str, SemanticDimensionScore]:
        """
        Evaluate semantic similarity between a source and target rule.

        Args:
            source_rule: Source rule content
            target_rule: Target rule content
            source_type: Source SIEM type
            target_type: Target SIEM type

        Returns:
            Dictionary of dimension scores
        """
        if not source_rule.strip() or not target_rule.strip():
            self.logger.warning("Empty source or target rule")
            return {
                dimension: SemanticDimensionScore(
                    dimension=dimension,
                    score=0.0,
                    reasoning="Empty rule content",
                    details="Cannot evaluate empty rules",
                )
                for dimension in self.SEMANTIC_DIMENSIONS.keys()
            }

        prompt = self.build_evaluation_prompt(
            source_rule, target_rule, source_type, target_type
        )
        llm_result = self.call_llm_for_evaluation(prompt)

        # Convert to SemanticDimensionScore objects
        dimension_scores = {}
        for dimension, result in llm_result.items():
            dimension_scores[dimension] = SemanticDimensionScore(
                dimension=dimension,
                score=float(result["score"]),
                reasoning=result["reasoning"],
                details=result["details"],
            )

        return dimension_scores

    def evaluate_single_result(self, file_info: Dict) -> Optional[LLMJudgeResult]:
        """
        Evaluate LLM judge for a single conversion result.

        Args:
            file_info: File information dictionary

        Returns:
            LLMJudgeResult or None if evaluation fails
        """
        try:
            data = file_info["data"]

            # Extract rule stages
            stages = self.extract_rule_stages(data)

            # Skip if no rules found
            if not stages["source_rule"] or not stages["direct_converted_rule"]:
                self.logger.warning(f"No rules found in {file_info['file_path']}")
                return None

            source_type = file_info["source_type"]
            target_type = file_info["target_type"]

            # Evaluate direct conversion
            self.logger.debug(
                f"Evaluating direct conversion for {file_info['file_name']}"
            )
            direct_scores = self.evaluate_rule_pair(
                stages["source_rule"],
                stages["direct_converted_rule"],
                source_type,
                target_type,
            )

            # Evaluate syntax optimization
            syntax_scores = {}
            if stages["syntax_optimized_rule"]:
                self.logger.debug(
                    f"Evaluating syntax optimization for {file_info['file_name']}"
                )
                syntax_scores = self.evaluate_rule_pair(
                    stages["source_rule"],
                    stages["syntax_optimized_rule"],
                    source_type,
                    target_type,
                )
            else:
                # Use direct conversion scores if no syntax optimization
                syntax_scores = direct_scores

            # Evaluate semantic optimization
            semantic_scores = {}
            if stages["semantic_optimized_rule"]:
                self.logger.debug(
                    f"Evaluating semantic optimization for {file_info['file_name']}"
                )
                semantic_scores = self.evaluate_rule_pair(
                    stages["source_rule"],
                    stages["semantic_optimized_rule"],
                    source_type,
                    target_type,
                )
            else:
                # Use syntax optimization scores if no semantic optimization
                semantic_scores = syntax_scores

            # Calculate overall scores
            direct_overall = sum(score.score for score in direct_scores.values()) / len(
                direct_scores
            )
            syntax_overall = sum(score.score for score in syntax_scores.values()) / len(
                syntax_scores
            )
            semantic_overall = sum(
                score.score for score in semantic_scores.values()
            ) / len(semantic_scores)

            # Extract rule name
            rule_name = self._extract_rule_name(file_info["file_name"], data)

            result = LLMJudgeResult(
                source_rule_type=source_type,
                target_rule_type=target_type,
                rule_name=rule_name,
                source_rule=stages["source_rule"],
                direct_converted_rule=stages["direct_converted_rule"],
                syntax_optimized_rule=stages["syntax_optimized_rule"],
                semantic_optimized_rule=stages["semantic_optimized_rule"],
                direct_conversion_scores=direct_scores,
                syntax_optimization_scores=syntax_scores,
                semantic_optimization_scores=semantic_scores,
                direct_conversion_overall=direct_overall,
                syntax_optimization_overall=syntax_overall,
                semantic_optimization_overall=semantic_overall,
                file_path=file_info["file_path"],
                evaluation_timestamp=pd.Timestamp.now().isoformat(),
                llm_model=self.model,
            )

            return result

        except Exception as e:
            self.logger.error(f"Failed to evaluate {file_info['file_path']}: {e}")
            return None

    def _extract_rule_name(self, file_name: str, data: Dict) -> str:
        """
        Extract rule name from file name or data.

        Args:
            file_name: Name of the file
            data: Conversion data

        Returns:
            Rule name
        """
        # Try to get from data first
        if "rule_name" in data:
            return data["rule_name"]

        # Extract from file name
        # Format: SourceType_to_TargetType_RuleName_timestamp.json
        parts = file_name.split("_")
        if len(parts) >= 4:
            # Find the rule name part (between target type and timestamp)
            rule_parts = []
            found_target_type = False

            for part in parts:
                if found_target_type and not part.replace("-", "").isdigit():
                    rule_parts.append(part)
                elif part in ["to"]:
                    found_target_type = True
                elif found_target_type and part.replace("-", "").isdigit():
                    break

            if rule_parts:
                return "_".join(rule_parts)

        # Fallback to file name without extension
        return Path(file_name).stem

    def evaluate_all_results(
        self,
        result_dir: str = "result",
        max_results: int = None,
        max_per_conversion_type: int = 10,
    ) -> List[LLMJudgeResult]:
        """
        Evaluate LLM judge for all conversion results.

        Args:
            result_dir: Directory containing conversion results
            max_results: Maximum number of results to evaluate (for testing)
            max_per_conversion_type: Maximum number of results per conversion type (default: 10)

        Returns:
            List of evaluation results
        """
        self.logger.info("Starting LLM judge evaluation")

        # Load all results
        file_infos = self.load_conversion_results(result_dir)

        if not file_infos:
            self.logger.warning("No conversion results found")
            return []

        # Group by conversion type and limit each type
        conversion_type_groups = {}
        for file_info in file_infos:
            conv_type = f"{file_info['source_type']} -> {file_info['target_type']}"
            if conv_type not in conversion_type_groups:
                conversion_type_groups[conv_type] = []
            conversion_type_groups[conv_type].append(file_info)

        # Limit results per conversion type
        limited_file_infos = []
        for conv_type, type_files in conversion_type_groups.items():
            # Take up to max_per_conversion_type files from each conversion type
            limited_files = type_files[:max_per_conversion_type]
            limited_file_infos.extend(limited_files)
            self.logger.info(
                f"Conversion type '{conv_type}': {len(limited_files)}/{len(type_files)} files selected"
            )

        # Apply global limit if specified
        if max_results:
            limited_file_infos = limited_file_infos[:max_results]
            self.logger.info(f"Limited to {max_results} results for evaluation")

        self.logger.info(f"Total files to evaluate: {len(limited_file_infos)}")

        # Evaluate each result with progress bar
        results = []
        with tqdm(
            total=len(limited_file_infos), desc="Evaluating rules", unit="rule"
        ) as pbar:
            for i, file_info in enumerate(limited_file_infos, 1):
                pbar.set_description(f"Evaluating: {file_info['file_name'][:50]}...")

                result = self.evaluate_single_result(file_info)
                if result:
                    results.append(result)
                    pbar.set_postfix(
                        {
                            "Success": len(results),
                            "Failed": i - len(results),
                            "Current": f"{result.direct_conversion_overall:.1f}",
                        }
                    )
                else:
                    pbar.set_postfix(
                        {
                            "Success": len(results),
                            "Failed": i - len(results),
                            "Current": "Failed",
                        }
                    )

                pbar.update(1)

        self.logger.info(f"Completed evaluation of {len(results)} rules")
        return results

    def generate_summary_report(self, results: List[LLMJudgeResult]) -> Dict:
        """
        Generate a summary report of the evaluation results.

        Args:
            results: List of evaluation results

        Returns:
            Summary report dictionary
        """
        if not results:
            return {"error": "No results to summarize"}

        # Group by conversion type
        conversion_types = {}
        for result in results:
            key = f"{result.source_rule_type} -> {result.target_rule_type}"
            if key not in conversion_types:
                conversion_types[key] = []
            conversion_types[key].append(result)

        summary = {
            "total_rules_evaluated": len(results),
            "conversion_types": len(conversion_types),
            "conversion_type_summaries": {},
            "dimension_summaries": {},
        }

        # Calculate statistics for each conversion type
        for conv_type, type_results in conversion_types.items():
            # Overall scores
            direct_scores = [r.direct_conversion_overall for r in type_results]
            syntax_scores = [r.syntax_optimization_overall for r in type_results]
            semantic_scores = [r.semantic_optimization_overall for r in type_results]

            # Calculate dimension-level scores for each optimization stage
            direct_dimension_scores = {}
            syntax_dimension_scores = {}
            semantic_dimension_scores = {}

            for dimension in self.SEMANTIC_DIMENSIONS.keys():
                # Direct conversion dimension scores
                direct_dim_scores = [
                    r.direct_conversion_scores[dimension].score for r in type_results
                ]
                direct_dimension_scores[dimension] = {
                    "mean_score": sum(direct_dim_scores) / len(direct_dim_scores),
                    "min_score": min(direct_dim_scores),
                    "max_score": max(direct_dim_scores),
                }

                # Syntax optimization dimension scores
                syntax_dim_scores = [
                    r.syntax_optimization_scores[dimension].score for r in type_results
                ]
                syntax_dimension_scores[dimension] = {
                    "mean_score": sum(syntax_dim_scores) / len(syntax_dim_scores),
                    "min_score": min(syntax_dim_scores),
                    "max_score": max(syntax_dim_scores),
                }

                # Semantic optimization dimension scores
                semantic_dim_scores = [
                    r.semantic_optimization_scores[dimension].score
                    for r in type_results
                ]
                semantic_dimension_scores[dimension] = {
                    "mean_score": sum(semantic_dim_scores) / len(semantic_dim_scores),
                    "min_score": min(semantic_dim_scores),
                    "max_score": max(semantic_dim_scores),
                }

            summary["conversion_type_summaries"][conv_type] = {
                "total_rules": len(type_results),
                "direct_conversion": {
                    "overall": {
                        "mean_score": sum(direct_scores) / len(direct_scores),
                        "min_score": min(direct_scores),
                        "max_score": max(direct_scores),
                    },
                    "dimensions": direct_dimension_scores,
                },
                "syntax_optimization": {
                    "overall": {
                        "mean_score": sum(syntax_scores) / len(syntax_scores),
                        "min_score": min(syntax_scores),
                        "max_score": max(syntax_scores),
                    },
                    "dimensions": syntax_dimension_scores,
                },
                "semantic_optimization": {
                    "overall": {
                        "mean_score": sum(semantic_scores) / len(semantic_scores),
                        "min_score": min(semantic_scores),
                        "max_score": max(semantic_scores),
                    },
                    "dimensions": semantic_dimension_scores,
                },
            }

        # Calculate dimension-level statistics
        for dimension in self.SEMANTIC_DIMENSIONS.keys():
            all_scores = []
            for result in results:
                all_scores.extend(
                    [
                        result.direct_conversion_scores[dimension].score,
                        result.syntax_optimization_scores[dimension].score,
                        result.semantic_optimization_scores[dimension].score,
                    ]
                )

            summary["dimension_summaries"][dimension] = {
                "dimension_name": self.SEMANTIC_DIMENSIONS[dimension],
                "mean_score": sum(all_scores) / len(all_scores),
                "min_score": min(all_scores),
                "max_score": max(all_scores),
            }

        return summary

    def save_results(
        self,
        results: List[LLMJudgeResult],
        output_file: str = "evaluation/llm_judge_results.json",
    ):
        """
        Save evaluation results to a JSON file.

        Args:
            results: List of evaluation results
            output_file: Output file path
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(exist_ok=True)

        # Convert results to dictionaries
        results_data = []
        for result in results:
            result_dict = {
                "source_rule_type": result.source_rule_type,
                "target_rule_type": result.target_rule_type,
                "rule_name": result.rule_name,
                "source_rule": result.source_rule,
                "direct_converted_rule": result.direct_converted_rule,
                "syntax_optimized_rule": result.syntax_optimized_rule,
                "semantic_optimized_rule": result.semantic_optimized_rule,
                "direct_conversion_scores": {
                    dim: {
                        "score": score.score,
                        "reasoning": score.reasoning,
                        "details": score.details,
                    }
                    for dim, score in result.direct_conversion_scores.items()
                },
                "syntax_optimization_scores": {
                    dim: {
                        "score": score.score,
                        "reasoning": score.reasoning,
                        "details": score.details,
                    }
                    for dim, score in result.syntax_optimization_scores.items()
                },
                "semantic_optimization_scores": {
                    dim: {
                        "score": score.score,
                        "reasoning": score.reasoning,
                        "details": score.details,
                    }
                    for dim, score in result.semantic_optimization_scores.items()
                },
                "direct_conversion_overall": result.direct_conversion_overall,
                "syntax_optimization_overall": result.syntax_optimization_overall,
                "semantic_optimization_overall": result.semantic_optimization_overall,
                "file_path": result.file_path,
                "evaluation_timestamp": result.evaluation_timestamp,
                "llm_model": result.llm_model,
            }
            results_data.append(result_dict)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Saved {len(results)} evaluation results to {output_path}")

    def save_summary_report(
        self, summary: Dict, output_file: str = "evaluation/llm_judge_summary.json"
    ):
        """
        Save summary report to a JSON file.

        Args:
            summary: Summary report dictionary
            output_file: Output file path
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Saved summary report to {output_path}")


def main():
    """Main function to run the LLM judge evaluation."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Evaluate rule conversion using LLM as a judge"
    )
    parser.add_argument(
        "--result-dir", default="result", help="Directory containing conversion results"
    )
    parser.add_argument(
        "--output-dir", default="evaluation", help="Output directory for results"
    )
    parser.add_argument(
        "--model", default="gpt-4o-mini", help="LLM model to use for evaluation"
    )
    parser.add_argument(
        "--max-results", type=int, help="Maximum number of results to evaluate"
    )
    parser.add_argument(
        "--max-per-conversion-type",
        type=int,
        default=10,
        help="Maximum number of results per conversion type (default: 10)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize evaluator
    evaluator = LLMJudgeEvaluator(model=args.model)

    # Run evaluation
    results = evaluator.evaluate_all_results(
        args.result_dir, args.max_results, args.max_per_conversion_type
    )

    if results:
        # Generate summary
        summary = evaluator.generate_summary_report(results)

        # Save results
        evaluator.save_results(results, f"{args.output_dir}/llm_judge_results.json")
        evaluator.save_summary_report(
            summary, f"{args.output_dir}/llm_judge_summary.json"
        )

        # Print summary
        print(f"\n=== LLM Judge Evaluation Summary ===")
        print(f"Total rules evaluated: {summary['total_rules_evaluated']}")
        print(f"Conversion types: {summary['conversion_types']}")

        print(f"\n=== Dimension Summary ===")
        for dimension, stats in summary["dimension_summaries"].items():
            print(f"{dimension} ({stats['dimension_name']}): {stats['mean_score']:.2f}")

        print(f"\n=== Conversion Type Summary ===")
        for conv_type, stats in summary["conversion_type_summaries"].items():
            print(f"\n{conv_type}:")
            print(
                f"  Direct Conversion: {stats['direct_conversion']['overall']['mean_score']:.2f}"
            )
            print(
                f"  Syntax Optimization: {stats['syntax_optimization']['overall']['mean_score']:.2f}"
            )
            print(
                f"  Semantic Optimization: {stats['semantic_optimization']['overall']['mean_score']:.2f}"
            )

            # Show dimension breakdown for each stage
            print(f"\n  Dimension Breakdown:")
            print(f"    Direct Conversion Dimensions:")
            for dim, dim_stats in stats["direct_conversion"]["dimensions"].items():
                print(f"      {dim}: {dim_stats['mean_score']:.2f}")

            print(f"    Syntax Optimization Dimensions:")
            for dim, dim_stats in stats["syntax_optimization"]["dimensions"].items():
                print(f"      {dim}: {dim_stats['mean_score']:.2f}")

            print(f"    Semantic Optimization Dimensions:")
            for dim, dim_stats in stats["semantic_optimization"]["dimensions"].items():
                print(f"      {dim}: {dim_stats['mean_score']:.2f}")
    else:
        print("No results to evaluate")


if __name__ == "__main__":
    main()
