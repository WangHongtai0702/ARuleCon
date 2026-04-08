"""
Embedding-based similarity evaluation for rule conversion results.

This module implements similarity evaluation using OpenAI's embedding models
to compare source rules with target rules at different conversion stages.
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import numpy as np
from dataclasses import dataclass
import pandas as pd

from openai import OpenAI
from sklearn.metrics.pairwise import cosine_similarity
from dotenv import load_dotenv


@dataclass
class RuleEmbeddingResult:
    """Result of embedding similarity evaluation for a single rule."""

    source_rule_type: str
    target_rule_type: str
    rule_name: str
    source_rule: str

    # Different stages of target rule
    direct_conversion_rule: str
    syntax_optimization_rule: str
    semantic_optimization_rule: str

    # Embedding similarities
    direct_conversion_similarity: float
    syntax_optimization_similarity: float
    semantic_optimization_similarity: float

    # Metadata
    file_path: str
    evaluation_timestamp: str


class EmbeddingSimilarityEvaluator:
    """Evaluator for rule similarity using OpenAI embeddings."""

    def __init__(self, model: str = "text-embedding-3-small", api_key: str = None):
        """
        Initialize the embedding similarity evaluator.

        Args:
            model: OpenAI embedding model to use
            api_key: OpenAI API key (if None, loads from .env file or environment variable)
        """
        # Load environment variables from .env file
        load_dotenv()

        self.model = model

        # Get API key from parameter, .env file, or environment variable
        if api_key is None:
            api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise ValueError(
                "OpenAI API key not found. Please set it in one of the following ways:\n"
                "1. Pass api_key parameter to EmbeddingSimilarityEvaluator()\n"
                "2. Set OPENAI_API_KEY in .env file\n"
                "3. Set OPENAI_API_KEY environment variable"
            )

        self.client = OpenAI(api_key=api_key)
        self.logger = logging.getLogger(__name__)

        # Cache for embeddings to avoid redundant API calls
        self.embedding_cache = {}

    def get_embedding(self, text: str) -> List[float]:
        """
        Get embedding for a given text using OpenAI API.

        Args:
            text: Text to embed

        Returns:
            List of embedding values
        """
        # Ensure text is a string and not empty
        if not text or not isinstance(text, str):
            self.logger.warning(f"Invalid text for embedding: {type(text)} - {text}")
            return None

        # Check cache first
        if text in self.embedding_cache:
            return self.embedding_cache[text]

        try:
            # Clean text for embedding
            cleaned_text = self._clean_text_for_embedding(text)

            response = self.client.embeddings.create(
                model=self.model, input=cleaned_text
            )

            embedding = response.data[0].embedding
            self.embedding_cache[text] = embedding

            return embedding

        except Exception as e:
            self.logger.error(f"Failed to get embedding for text: {e}")
            return None

    def _clean_text_for_embedding(self, text: str) -> str:
        """
        Clean text for better embedding quality.

        Args:
            text: Raw text

        Returns:
            Cleaned text
        """
        if not text:
            return ""

        # Remove excessive whitespace
        cleaned = " ".join(text.split())

        # Remove common rule metadata that might not be relevant for similarity
        # Keep the core rule logic
        return cleaned

    def calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate cosine similarity between two texts.

        Args:
            text1: First text
            text2: Second text

        Returns:
            Cosine similarity score (0-1)
        """
        embedding1 = self.get_embedding(text1)
        embedding2 = self.get_embedding(text2)

        if embedding1 is None or embedding2 is None:
            return 0.0

        # Calculate cosine similarity
        similarity = cosine_similarity([embedding1], [embedding2])[0][0]
        return float(similarity)

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

    def extract_rule_stages(self, conversion_data: Dict) -> Dict[str, str]:
        """
        Extract rules from different conversion stages.

        Args:
            conversion_data: Conversion result data

        Returns:
            Dictionary with rules from different stages
        """
        stages = {}

        # Source rule - handle both string and dict formats
        source_rule = conversion_data.get("source_rule", "")
        if isinstance(source_rule, dict):
            # Extract rule content from dict format
            stages["source_rule"] = (
                source_rule.get("rule_content", "")
                or source_rule.get("search_query", "")
                or str(source_rule)
            )
        else:
            stages["source_rule"] = str(source_rule) if source_rule else ""

        # Direct conversion
        direct_conversion = conversion_data.get("direct_conversion", {})
        if direct_conversion.get("success", False):
            stages["direct_conversion_rule"] = direct_conversion.get(
                "converted_rule", ""
            )
        else:
            stages["direct_conversion_rule"] = ""

        # Syntax optimization
        syntax_optimization = conversion_data.get("syntax_optimization", {})
        if syntax_optimization.get("success", False):
            stages["syntax_optimization_rule"] = syntax_optimization.get(
                "optimized_rule", ""
            )
        else:
            stages["syntax_optimization_rule"] = ""

        # Semantic optimization
        semantic_optimization = conversion_data.get("semantic_optimization", {})
        if semantic_optimization.get("success", False):
            stages["semantic_optimization_rule"] = semantic_optimization.get(
                "optimized_rule", ""
            )
        else:
            stages["semantic_optimization_rule"] = ""

        return stages

    def evaluate_single_result(self, file_info: Dict) -> Optional[RuleEmbeddingResult]:
        """
        Evaluate embedding similarity for a single conversion result.

        Args:
            file_info: File information dictionary

        Returns:
            RuleEmbeddingResult or None if evaluation fails
        """
        try:
            data = file_info["data"]
            stages = self.extract_rule_stages(data)

            # Skip if no source rule
            if not stages["source_rule"]:
                self.logger.warning(f"No source rule found in {file_info['file_path']}")
                return None

            # Calculate similarities
            source_rule = stages["source_rule"]

            direct_similarity = 0.0
            if stages["direct_conversion_rule"]:
                direct_similarity = self.calculate_similarity(
                    source_rule, stages["direct_conversion_rule"]
                )

            syntax_similarity = 0.0
            if stages["syntax_optimization_rule"]:
                syntax_similarity = self.calculate_similarity(
                    source_rule, stages["syntax_optimization_rule"]
                )

            semantic_similarity = 0.0
            if stages["semantic_optimization_rule"]:
                semantic_similarity = self.calculate_similarity(
                    source_rule, stages["semantic_optimization_rule"]
                )

            # Extract rule name from file name or data
            rule_name = self._extract_rule_name(file_info["file_name"], data)

            result = RuleEmbeddingResult(
                source_rule_type=file_info["source_type"],
                target_rule_type=file_info["target_type"],
                rule_name=rule_name,
                source_rule=source_rule,
                direct_conversion_rule=stages["direct_conversion_rule"],
                syntax_optimization_rule=stages["syntax_optimization_rule"],
                semantic_optimization_rule=stages["semantic_optimization_rule"],
                direct_conversion_similarity=direct_similarity,
                syntax_optimization_similarity=syntax_similarity,
                semantic_optimization_similarity=semantic_similarity,
                file_path=file_info["file_path"],
                evaluation_timestamp=pd.Timestamp.now().isoformat(),
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
            target_type = parts[2]  # Target type
            rule_parts = []
            for i, part in enumerate(parts[3:], 3):
                if part.isdigit() and len(part) >= 4:  # Likely timestamp
                    break
                rule_parts.append(part)

            if rule_parts:
                return "_".join(rule_parts)

        # Fallback to file name without extension
        return Path(file_name).stem

    def evaluate_all_results(
        self, result_dir: str = "result"
    ) -> List[RuleEmbeddingResult]:
        """
        Evaluate embedding similarity for all conversion results.

        Args:
            result_dir: Directory containing conversion results

        Returns:
            List of evaluation results
        """
        self.logger.info("Starting embedding similarity evaluation")

        # Load all results
        file_infos = self.load_conversion_results(result_dir)

        if not file_infos:
            self.logger.warning("No conversion results found")
            return []

        # Evaluate each result
        results = []
        for i, file_info in enumerate(file_infos, 1):
            self.logger.info(
                f"Evaluating {i}/{len(file_infos)}: {file_info['file_name']}"
            )

            result = self.evaluate_single_result(file_info)
            if result:
                results.append(result)

        self.logger.info(f"Completed evaluation of {len(results)} rules")
        return results

    def generate_summary_report(self, results: List[RuleEmbeddingResult]) -> Dict:
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
        }

        # Calculate statistics for each conversion type
        for conv_type, type_results in conversion_types.items():
            direct_scores = [
                r.direct_conversion_similarity
                for r in type_results
                if r.direct_conversion_similarity > 0
            ]
            syntax_scores = [
                r.syntax_optimization_similarity
                for r in type_results
                if r.syntax_optimization_similarity > 0
            ]
            semantic_scores = [
                r.semantic_optimization_similarity
                for r in type_results
                if r.semantic_optimization_similarity > 0
            ]

            summary["conversion_type_summaries"][conv_type] = {
                "total_rules": len(type_results),
                "direct_conversion": {
                    "count": len(direct_scores),
                    "mean_similarity": np.mean(direct_scores) if direct_scores else 0.0,
                    "std_similarity": np.std(direct_scores) if direct_scores else 0.0,
                    "min_similarity": np.min(direct_scores) if direct_scores else 0.0,
                    "max_similarity": np.max(direct_scores) if direct_scores else 0.0,
                },
                "syntax_optimization": {
                    "count": len(syntax_scores),
                    "mean_similarity": np.mean(syntax_scores) if syntax_scores else 0.0,
                    "std_similarity": np.std(syntax_scores) if syntax_scores else 0.0,
                    "min_similarity": np.min(syntax_scores) if syntax_scores else 0.0,
                    "max_similarity": np.max(syntax_scores) if syntax_scores else 0.0,
                },
                "semantic_optimization": {
                    "count": len(semantic_scores),
                    "mean_similarity": (
                        np.mean(semantic_scores) if semantic_scores else 0.0
                    ),
                    "std_similarity": (
                        np.std(semantic_scores) if semantic_scores else 0.0
                    ),
                    "min_similarity": (
                        np.min(semantic_scores) if semantic_scores else 0.0
                    ),
                    "max_similarity": (
                        np.max(semantic_scores) if semantic_scores else 0.0
                    ),
                },
            }

        return summary

    def save_results(
        self,
        results: List[RuleEmbeddingResult],
        output_file: str = "evaluation/embedding_similarity_results.json",
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
                "direct_conversion_rule": result.direct_conversion_rule,
                "syntax_optimization_rule": result.syntax_optimization_rule,
                "semantic_optimization_rule": result.semantic_optimization_rule,
                "direct_conversion_similarity": result.direct_conversion_similarity,
                "syntax_optimization_similarity": result.syntax_optimization_similarity,
                "semantic_optimization_similarity": result.semantic_optimization_similarity,
                "file_path": result.file_path,
                "evaluation_timestamp": result.evaluation_timestamp,
            }
            results_data.append(result_dict)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Saved {len(results)} evaluation results to {output_path}")

    def save_summary_report(
        self,
        summary: Dict,
        output_file: str = "evaluation/embedding_similarity_summary.json",
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
    """Main function to run the embedding similarity evaluation."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Evaluate rule conversion similarity using embeddings"
    )
    parser.add_argument(
        "--result-dir", default="result", help="Directory containing conversion results"
    )
    parser.add_argument(
        "--model",
        default="text-embedding-3-small",
        help="OpenAI embedding model to use",
    )
    parser.add_argument(
        "--output-dir", default="evaluation", help="Output directory for results"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize evaluator
    evaluator = EmbeddingSimilarityEvaluator(model=args.model)

    # Run evaluation
    results = evaluator.evaluate_all_results(args.result_dir)

    if results:
        # Generate summary
        summary = evaluator.generate_summary_report(results)

        # Save results
        evaluator.save_results(
            results, f"{args.output_dir}/embedding_similarity_results.json"
        )
        evaluator.save_summary_report(
            summary, f"{args.output_dir}/embedding_similarity_summary.json"
        )

        # Print summary
        print(f"\n=== Embedding Similarity Evaluation Summary ===")
        print(f"Total rules evaluated: {summary['total_rules_evaluated']}")
        print(f"Conversion types: {summary['conversion_types']}")

        for conv_type, stats in summary["conversion_type_summaries"].items():
            print(f"\n{conv_type}:")
            print(
                f"  Direct Conversion: {stats['direct_conversion']['mean_similarity']:.3f} ± {stats['direct_conversion']['std_similarity']:.3f}"
            )
            print(
                f"  Syntax Optimization: {stats['syntax_optimization']['mean_similarity']:.3f} ± {stats['syntax_optimization']['std_similarity']:.3f}"
            )
            print(
                f"  Semantic Optimization: {stats['semantic_optimization']['mean_similarity']:.3f} ± {stats['semantic_optimization']['std_similarity']:.3f}"
            )
    else:
        print("No results to evaluate")


if __name__ == "__main__":
    main()
