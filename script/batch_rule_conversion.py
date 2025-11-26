#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))
sys.path.append(str(project_root / "src"))

from src.utils.dataset import get_siem_dataset, MultiSIEMDataset
from src.core.rule_converter import RuleConverter, generate_ir, generate_rule_from_ir
from src.core.rule_optimizer import SyntaxRuleOptimizer, SemanticRuleOptimizer
from src.utils.conversion_logger import ConversionLogger


class BatchRuleConverter:
    """批量规则转换器"""

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

    def get_available_rules(
        self, siem_type: str, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """获取指定SIEM类型的规则"""
        try:
            dataset = get_siem_dataset(siem_type)
            rules = []

            for i, rule in enumerate(dataset):
                if limit and i >= limit:
                    break

                rule_data = {
                    "rule_name": rule.rule_name,
                    "rule_content": rule.rule_content,
                    "search_query": rule.search_query,
                    "description": rule.description,
                    "author": rule.author,
                    "file_path": str(rule.file_path),
                    "file_type": rule.file_type,
                    "tags": rule.tags or [],
                    "metadata": rule.metadata or {},
                }
                rules.append(rule_data)

            return rules
        except Exception as e:
            print(f"Error loading {siem_type} rules: {e}")
            return []

    def convert_single_rule(
        self, source_rule: Dict[str, Any], source_type: str, target_type: str
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
                model="gpt-4o-mini",
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
                ir_data=ir_result, target_rule_type=target_type, model="gpt-4o-mini"
            )
            result["direct_conversion"] = {
                "converted_rule": conversion_result,
                "success": True,
                "metadata": {},
            }

            # 3. 语法优化
            print(f"  Applying syntax optimization: {source_rule['rule_name']}")
            try:
                # 生成优化任务列表
                todo_list = self.syntax_optimizer.generate_optimization_todo_list(
                    init_rule=conversion_result, rule_type=target_type
                )

                if todo_list:
                    # 完成所有优化任务
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
                    converted_ir=ir_result,  # 使用相同的IR作为简化
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

    def batch_convert(
        self, source_type: str, target_type: str, num_rules: int, output_dir: Path
    ) -> str:
        """批量转换规则"""
        print(f"Starting batch conversion: {source_type} -> {target_type}")
        print(f"Number of rules to convert: {num_rules}")

        # 获取源规则
        print(f"Loading {source_type} rules...")
        source_rules = self.get_available_rules(source_type, num_rules)

        if not source_rules:
            print(f"No rules found for {source_type}")
            return None

        print(f"Found {len(source_rules)} rules from {source_type}")

        # 创建输出目录
        output_dir.mkdir(parents=True, exist_ok=True)

        # 转换规则并逐个保存
        conversion_results = []
        successful_conversions = 0
        saved_files = []

        for i, source_rule in enumerate(source_rules, 1):
            print(
                f"\nConverting rule {i}/{len(source_rules)}: {source_rule['rule_name']}"
            )
            if source_rule["rule_content"] is None:
                continue
            if source_rule["rule_content"] == "":
                continue
            if source_rule["rule_content"] == "null":
                continue
            if source_rule["rule_content"] == "undefined":
                continue
            if source_rule["rule_content"] == "NaN":
                continue
            conversion_result = self.convert_single_rule(
                source_rule, source_type, target_type
            )
            conversion_results.append(conversion_result)

            if not conversion_result["errors"]:
                successful_conversions += 1

            # 为每个规则生成单独的输出文件
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            rule_name_safe = (
                source_rule["rule_name"]
                .replace(" ", "_")
                .replace("/", "_")
                .replace("\\", "_")
            )
            output_filename = (
                f"{source_type}_to_{target_type}_{rule_name_safe}_{timestamp}.json"
            )
            output_path = output_dir / output_filename

            # 保存单个规则的结果
            single_rule_data = {
                "conversion_summary": {
                    "source_type": source_type,
                    "target_type": target_type,
                    "rule_index": i,
                    "total_rules": len(source_rules),
                    "rule_name": source_rule["rule_name"],
                    "conversion_timestamp": datetime.now().isoformat(),
                    "success": not bool(conversion_result["errors"]),
                },
                "source_rule": conversion_result["source_rule"],
                "conversion_info": conversion_result["conversion_info"],
                "ir_generation": conversion_result["ir_generation"],
                "direct_conversion": conversion_result["direct_conversion"],
                "syntax_optimization": conversion_result["syntax_optimization"],
                "semantic_optimization": conversion_result["semantic_optimization"],
                "errors": conversion_result["errors"],
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(single_rule_data, f, indent=2, ensure_ascii=False)

            saved_files.append(str(output_path))
            print(f"  💾 Saved: {output_path}")

        print(f"\nConversion completed!")
        print(f"Successful conversions: {successful_conversions}/{len(source_rules)}")
        print(f"Individual rule files: {len(saved_files)} files")
        print(f"Output directory: {output_dir}")

        return str(output_dir)

    def list_available_siems(self):
        """列出可用的SIEM类型"""
        print("Available SIEM types:")
        for i, siem in enumerate(self.supported_siems, 1):
            print(f"  {i}. {siem}")

    def get_rule_count(self, siem_type: str) -> int:
        """获取指定SIEM类型的规则数量"""
        try:
            dataset = get_siem_dataset(siem_type)
            count = sum(1 for _ in dataset)
            return count
        except Exception as e:
            print(f"Error getting rule count for {siem_type}: {e}")
            return 0


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="批量规则转换工具")
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
        help="目标规则类型",
    )
    parser.add_argument(
        "--num-rules", "-n", type=int, default=10, help="转换规则数量 (默认: 10)"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        help="输出目录 (默认: result/{source_type}/{target_type})",
    )
    parser.add_argument(
        "--list-siems", "-l", action="store_true", help="列出可用的SIEM类型"
    )
    parser.add_argument("--count", "-c", type=str, help="获取指定SIEM类型的规则数量")

    args = parser.parse_args()

    converter = BatchRuleConverter()

    # 列出可用的SIEM类型
    if args.list_siems:
        converter.list_available_siems()
        return

    # 获取规则数量
    if args.count:
        if args.count not in converter.supported_siems:
            print(f"Invalid SIEM type: {args.count}")
            return
        count = converter.get_rule_count(args.count)
        print(f"{args.count} rules available: {count}")
        return

    # 验证参数
    if not args.source or not args.target:
        print("Error: Both --source and --target are required")
        print("Use --list-siems to see available SIEM types")
        return

    if args.source == args.target:
        print("Error: Source and target cannot be the same")
        return

    # 检查源规则数量
    source_count = converter.get_rule_count(args.source)
    if source_count == 0:
        print(f"No rules found for {args.source}")
        return

    if args.num_rules > source_count:
        print(
            f"Warning: Requested {args.num_rules} rules, but only {source_count} available"
        )
        args.num_rules = source_count

    # 设置默认输出目录
    if args.output_dir is None:
        output_dir = Path("result") / args.source / args.target
    else:
        output_dir = args.output_dir

    # 执行转换
    try:
        output_path = converter.batch_convert(
            source_type=args.source,
            target_type=args.target,
            num_rules=args.num_rules,
            output_dir=output_dir,
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
