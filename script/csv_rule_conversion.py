#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import argparse
import pandas as pd
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# Add project root directory to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))
sys.path.append(str(project_root / "src"))

from src.core.rule_converter import RuleConverter, generate_ir, generate_rule_from_ir
from src.core.rule_optimizer import SyntaxRuleOptimizer, SemanticRuleOptimizer
from src.utils.conversion_logger import ConversionLogger


class CSVRuleConverter:
    """CSV-based rule converter"""

    def __init__(self):
        self.rule_converter = RuleConverter()
        self.syntax_optimizer = SyntaxRuleOptimizer()
        self.semantic_optimizer = SemanticRuleOptimizer()
        self.supported_siems = [
            "Splunk",
            "Microsoft Sentinel",
            "Google Chronicle",
            "IBM QRadar",
            "RSA NetWitness",
        ]

    def load_csv_rules(
        self, csv_path: str, rule_column: str
    ) -> tuple[List[Dict[str, Any]], pd.DataFrame]:
        """Load rules from CSV file, return rule list and DataFrame"""
        try:
            # Read CSV with proper quoting to handle commas in fields
            df = pd.read_csv(csv_path, quoting=csv.QUOTE_ALL)
            
            # Check if column exists
            if rule_column not in df.columns:
                raise ValueError(f"Column '{rule_column}' not found in CSV")
            
            rules = []
            for idx, row in df.iterrows():
                rule_data = {
                    "rule_name": f"Rule_{idx + 1}",
                    "rule_content": str(row[rule_column]),
                    "row_number": idx + 1,
                    "all_data": row.to_dict(),
                }
                
                # Add other columns to rule data if available
                for col in df.columns:
                    if col != rule_column and col:
                        rule_data[col] = row[col]
                        if col.lower() in ['name', 'title', 'detection_name', 'rule_name']:
                            rule_data["rule_name"] = str(row[col])
                
                rules.append(rule_data)
            
            return rules, df
        except Exception as e:
            print(f"Error loading CSV: {e}")
            return [], pd.DataFrame()

    def convert_single_rule(
        self, source_rule: Dict[str, Any], source_type: str, target_type: str, model: str = "gpt-4o-mini"
    ) -> Dict[str, Any]:
        """Convert a single rule"""
        result = {
            "source_rule": source_rule,
            "conversion_info": {
                "source_type": source_type,
                "target_type": target_type,
                "timestamp": datetime.now().isoformat(),
            },
            "ir_generation": None,
            "direct_conversion": None,
            "syntax_optimization": None,
            "semantic_optimization": None,
            "errors": [],
        }

        try:
            # 1. Generate IR
            print(f"  Generating IR for: {source_rule['rule_name']}")
            ir_result = generate_ir(
                rule_content=source_rule["rule_content"],
                model=model,
                rule_type=source_type,
            )
            result["ir_generation"] = {
                "ir_content": ir_result,
                "success": True,
                "metadata": {},
            }

            # 2. Direct conversion
            print(f"  Converting IR to {target_type}: {source_rule['rule_name']}")
            conversion_result = generate_rule_from_ir(
                ir_data=ir_result, target_rule_type=target_type, model=model
            )
            result["direct_conversion"] = {
                "converted_rule": conversion_result,
                "success": True,
                "metadata": {},
            }

            # 3. Syntax optimization
            print(f"  Applying syntax optimization: {source_rule['rule_name']}")
            try:
                todo_list = self.syntax_optimizer.generate_optimization_todo_list(
                    init_rule=conversion_result, rule_type=target_type
                )

                if todo_list:
                    optimization_result = (
                        self.syntax_optimizer.complete_all_optimization_tasks(
                            todo_list=todo_list, original_rule=conversion_result
                        )
                    )

                    if optimization_result:
                        syntax_result = {
                            "optimized_rule": optimization_result.final_optimized_rule,
                            "optimization_suggestions": [
                                task.task_name for task in todo_list.tasks
                            ],
                            "success": True,
                            "metadata": {},
                        }
                    else:
                        syntax_result = {
                            "optimized_rule": conversion_result,
                            "optimization_suggestions": [],
                            "success": False,
                            "metadata": {
                                "error": "Failed to complete optimization tasks"
                            },
                        }
                else:
                    syntax_result = {
                        "optimized_rule": conversion_result,
                        "optimization_suggestions": [],
                        "success": False,
                        "metadata": {
                            "error": "Failed to generate optimization todo list"
                        },
                    }
            except Exception as e:
                syntax_result = {
                    "optimized_rule": conversion_result,
                    "optimization_suggestions": [],
                    "success": False,
                    "metadata": {"error": str(e)},
                }

            result["syntax_optimization"] = syntax_result

            # 4. Semantic optimization
            print(f"  Applying semantic optimization: {source_rule['rule_name']}")
            try:
                semantic_result = self.semantic_optimizer.optimize_rule_semantics(
                    original_rule=source_rule["rule_content"],
                    converted_rule=syntax_result.get(
                        "optimized_rule", conversion_result
                    ),
                    original_ir=ir_result,
                    converted_ir=ir_result,
                    source_rule_type=source_type,
                    target_rule_type=target_type,
                )
            except Exception as e:
                semantic_result = {
                    "optimized_rule": syntax_result.get(
                        "optimized_rule", conversion_result
                    ),
                    "optimization_suggestions": [],
                    "success": False,
                    "metadata": {"error": str(e)},
                }

            result["semantic_optimization"] = semantic_result

        except Exception as e:
            error_msg = f"Error converting rule {source_rule['rule_name']}: {str(e)}"
            print(f"  ERROR: {error_msg}")
            result["errors"].append(error_msg)

        return result

    def save_results_to_csv(
        self,
        csv_path: str,
        df: pd.DataFrame,
        conversion_results: List[Dict[str, Any]],
        target_type: str,
        target_column_name: str = None,
    ) -> str:
        """Save conversion results back to CSV file"""
        if target_column_name is None:
            target_column_name = f"converted_rule_{target_type}"
        
        # Add conversion results to DataFrame
        converted_rules = []
        for result in conversion_results:
            if result.get("semantic_optimization", {}).get("optimized_rule"):
                rule = result["semantic_optimization"]["optimized_rule"]
            elif result.get("syntax_optimization", {}).get("optimized_rule"):
                rule = result["syntax_optimization"]["optimized_rule"]
            elif result.get("direct_conversion", {}).get("converted_rule"):
                rule = result["direct_conversion"]["converted_rule"]
            else:
                rule = "ERROR: Conversion failed"
            converted_rules.append(rule)
        
        df[target_column_name] = converted_rules
        
        # Save to new file (add timestamp suffix)
        from datetime import datetime
        original_path = Path(csv_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = original_path.parent / f"{original_path.stem}_converted_{timestamp}{original_path.suffix}"
        
        df.to_csv(output_path, index=False, encoding='utf-8')
        
        print(f"\n💾 Converted CSV saved to: {output_path}")
        return str(output_path)

    def batch_convert(
        self,
        csv_path: str,
        rule_column: str,
        source_type: str,
        target_type: str,
        model: str = "gpt-4o-mini",
        save_to_csv: bool = True,
    ) -> str:
        """Batch convert rules"""
        print(f"Starting batch conversion from CSV: {csv_path}")
        print(f"Source type: {source_type} -> Target type: {target_type}")
        print(f"Rule column: {rule_column}")

        # Load rules from CSV
        print(f"Loading rules from CSV...")
        source_rules, original_df = self.load_csv_rules(csv_path, rule_column)

        if not source_rules:
            print(f"No rules found in CSV")
            return None

        print(f"Found {len(source_rules)} rules in CSV")

        # Convert rules
        conversion_results = []
        successful_conversions = 0

        for i, source_rule in enumerate(source_rules, 1):
            print(
                f"\nConverting rule {i}/{len(source_rules)}: {source_rule['rule_name']}"
            )

            conversion_result = self.convert_single_rule(
                source_rule, source_type, target_type, model
            )
            conversion_results.append(conversion_result)

            if not conversion_result["errors"]:
                successful_conversions += 1

        # Save conversion results back to CSV
        csv_output_path = None
        if save_to_csv:
            try:
                csv_output_path = self.save_results_to_csv(
                    csv_path=csv_path,
                    df=original_df,
                    conversion_results=conversion_results,
                    target_type=target_type,
                    target_column_name=f"converted_rule_{target_type}",
                )
            except Exception as e:
                print(f"Warning: Failed to save to CSV: {e}")

        print(f"\nConversion completed!")
        print(f"Successful conversions: {successful_conversions}/{len(source_rules)}")
        if csv_output_path:
            print(f"CSV with results: {csv_output_path}")

        return csv_output_path if csv_output_path else csv_path


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Batch rule conversion tool based on CSV input"
    )
    parser.add_argument(
        "--csv",
        "-f",
        type=str,
        required=True,
        help="CSV file path",
    )
    parser.add_argument(
        "--column",
        "-c",
        type=str,
        required=True,
        help="Column name containing rules",
    )
    parser.add_argument(
        "--source",
        "-s",
        choices=[
            "Splunk",
            "Microsoft Sentinel",
            "Google Chronicle",
            "IBM QRadar",
            "RSA NetWitness",
        ],
        required=True,
        help="Source rule type",
    )
    parser.add_argument(
        "--target",
        "-t",
        choices=[
            "Splunk",
            "Microsoft Sentinel",
            "Google Chronicle",
            "IBM QRadar",
            "RSA NetWitness",
        ],
        required=True,
        help="Target rule type",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        default="gpt-4o-mini",
        help="Model to use (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--csv-output-column",
        type=str,
        help="Column name for conversion results (default: converted_rule_{target_type})",
    )

    args = parser.parse_args()

    # Validate arguments
    if args.source == args.target:
        print("Error: Source and target cannot be the same")
        return

    # Check if CSV file exists
    if not Path(args.csv).exists():
        print(f"Error: CSV file not found: {args.csv}")
        return

    converter = CSVRuleConverter()

    # Execute conversion
    try:
        output_path = converter.batch_convert(
            csv_path=args.csv,
            rule_column=args.column,
            source_type=args.source,
            target_type=args.target,
            model=args.model,
            save_to_csv=True,
        )

        if output_path:
            print(f"\n✅ Conversion completed successfully!")
            print(f"📁 Results saved to: {output_path}")
        else:
            print("❌ Conversion failed")

    except KeyboardInterrupt:
        print("\n⚠️  Conversion interrupted by user")
    except Exception as e:
        print(f"❌ Conversion failed with error: {e}")


if __name__ == "__main__":
    main()

