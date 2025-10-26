#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import argparse
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))
sys.path.append(str(project_root / "src"))

from src.core.rule_converter import RuleConverter, generate_ir, generate_rule_from_ir
from src.core.rule_optimizer import SyntaxRuleOptimizer, SemanticRuleOptimizer
from src.utils.conversion_logger import ConversionLogger


class CSVRuleConverter:
    """基于CSV输入的规则转换器"""

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
        """从CSV文件加载规则，返回规则列表和DataFrame"""
        try:
            df = pd.read_csv(csv_path)
            
            # 检查列是否存在
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
                
                # 如果有其他有用的列，也添加到规则数据中
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
        """转换单个规则"""
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
            # 1. 生成IR
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

            # 2. 直接转换
            print(f"  Converting IR to {target_type}: {source_rule['rule_name']}")
            conversion_result = generate_rule_from_ir(
                ir_data=ir_result, target_rule_type=target_type, model=model
            )
            result["direct_conversion"] = {
                "converted_rule": conversion_result,
                "success": True,
                "metadata": {},
            }

            # 3. 语法优化
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

            # 4. 语义优化
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
        """将转换结果保存回CSV文件"""
        if target_column_name is None:
            target_column_name = f"converted_rule_{target_type}"
        
        # 添加转换结果列到DataFrame
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
        
        # 保存到新文件（添加_timestamp后缀）
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
        """批量转换规则"""
        print(f"Starting batch conversion from CSV: {csv_path}")
        print(f"Source type: {source_type} -> Target type: {target_type}")
        print(f"Rule column: {rule_column}")

        # 从CSV加载规则
        print(f"Loading rules from CSV...")
        source_rules, original_df = self.load_csv_rules(csv_path, rule_column)

        if not source_rules:
            print(f"No rules found in CSV")
            return None

        print(f"Found {len(source_rules)} rules in CSV")

        # 转换规则
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

        # 将转换结果保存回CSV
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
    """主函数"""
    parser = argparse.ArgumentParser(
        description="基于CSV输入的批量规则转换工具"
    )
    parser.add_argument(
        "--csv",
        "-f",
        type=str,
        required=True,
        help="CSV文件路径",
    )
    parser.add_argument(
        "--column",
        "-c",
        type=str,
        required=True,
        help="包含规则的列名称",
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
        help="源规则类型",
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
        help="目标规则类型",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        default="gpt-4o-mini",
        help="使用的模型 (默认: gpt-4o-mini)",
    )
    parser.add_argument(
        "--csv-output-column",
        type=str,
        help="转换结果列的名称 (默认: converted_rule_{target_type})",
    )

    args = parser.parse_args()

    # 验证参数
    if args.source == args.target:
        print("Error: Source and target cannot be the same")
        return

    # 检查CSV文件是否存在
    if not Path(args.csv).exists():
        print(f"Error: CSV file not found: {args.csv}")
        return

    converter = CSVRuleConverter()

    # 执行转换
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

