#!/usr/bin/env python3
"""
计算各个SIEM的规则条数

支持的SIEM类型和文件格式：
- Google Chronicle: .yaral 文件
- IBM QRadar: .txt 文件
- Microsoft Sentinel: .yaml 文件
- RSA NetWitness: .txt 文件
- Splunk: detections文件夹中的 .yml 文件
"""

import os
import glob
from pathlib import Path
from typing import Dict, Tuple


def count_siem_rules(dataset_path: str = "dataset") -> Dict[str, Dict[str, int]]:
    """
    计算各个SIEM的规则条数

    Args:
        dataset_path: 数据集根目录路径

    Returns:
        包含各SIEM规则统计信息的字典
    """
    results = {}

    # 定义各SIEM的规则路径和文件格式
    siem_configs = {
        "Google Chronicle": {
            "path": os.path.join(dataset_path, "rules", "Google Chronicle"),
            "pattern": "*.yaral",
            "description": "YARA-L rules",
            "recursive": True,
        },
        "IBM QRadar": {
            "path": os.path.join(dataset_path, "rules", "IBM QRadar"),
            "pattern": "*.txt",
            "description": "QRadar rules",
            "recursive": True,
        },
        "Microsoft Sentinel": {
            "path": os.path.join(dataset_path, "rules", "Microsoft Sentinel"),
            "pattern": "*.yaml",
            "description": "KQL rules",
            "recursive": True,
        },
        "RSA NetWitness": {
            "path": os.path.join(dataset_path, "rules", "RSA NetWitness"),
            "pattern": "*.txt",
            "description": "NetWitness rules",
            "recursive": True,
        },
        "Splunk": {
            "path": os.path.join(dataset_path, "rules", "Splunk", "detections"),
            "pattern": "*.yml",
            "description": "Splunk detection rules",
            "recursive": True,
        },
    }

    print("=== SIEM规则统计 ===\n")

    total_rules = 0

    for siem_name, config in siem_configs.items():
        path = config["path"]
        pattern = config["pattern"]
        description = config["description"]

        # 检查路径是否存在
        if not os.path.exists(path):
            print(f"❌ {siem_name}: 路径不存在 - {path}")
            results[siem_name] = {
                "count": 0,
                "path": path,
                "pattern": pattern,
                "description": description,
                "status": "路径不存在",
            }
            continue

        # 计算文件数量
        if config.get("recursive", False):
            # 递归搜索子目录
            search_pattern = os.path.join(path, "**", pattern)
            files = glob.glob(search_pattern, recursive=True)
        else:
            # 直接搜索指定路径
            search_pattern = os.path.join(path, pattern)
            files = glob.glob(search_pattern)

        rule_count = len(files)
        total_rules += rule_count

        # 显示结果
        status = "✅" if rule_count > 0 else "⚠️"
        print(f"{status} {siem_name}: {rule_count} 条规则")
        print(f"   路径: {path}")
        print(f"   格式: {pattern}")
        print(f"   描述: {description}")

        # 显示前几个文件示例
        if files:
            print(f"   示例文件:")
            for i, file_path in enumerate(files[:3], 1):
                filename = os.path.basename(file_path)
                print(f"     {i}. {filename}")
            if len(files) > 3:
                print(f"     ... 还有 {len(files) - 3} 个文件")
        print()

        # 保存结果
        results[siem_name] = {
            "count": rule_count,
            "path": path,
            "pattern": pattern,
            "description": description,
            "status": "成功" if rule_count > 0 else "无规则文件",
            "files": files[:10] if files else [],  # 保存前10个文件路径作为示例
        }

    # 显示总计
    print("=" * 50)
    print(f"📊 总计: {total_rules} 条规则")
    print("=" * 50)

    return results


def save_results_to_file(
    results: Dict[str, Dict[str, int]], output_file: str = "rule_count_report.txt"
):
    """
    将统计结果保存到文件

    Args:
        results: 统计结果字典
        output_file: 输出文件名
    """
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("SIEM规则统计报告\n")
        f.write("=" * 50 + "\n\n")

        total_rules = 0
        for siem_name, data in results.items():
            f.write(f"{siem_name}:\n")
            f.write(f"  规则数量: {data['count']}\n")
            f.write(f"  路径: {data['path']}\n")
            f.write(f"  文件格式: {data['pattern']}\n")
            f.write(f"  描述: {data['description']}\n")
            f.write(f"  状态: {data['status']}\n")

            if "files" in data and data["files"]:
                f.write(f"  示例文件:\n")
                for i, file_path in enumerate(data["files"], 1):
                    filename = os.path.basename(file_path)
                    f.write(f"    {i}. {filename}\n")

            f.write("\n")
            total_rules += data["count"]

        f.write("=" * 50 + "\n")
        f.write(f"总计: {total_rules} 条规则\n")

    print(f"📝 统计报告已保存到: {output_file}")


def main():
    """主函数"""
    print("开始统计SIEM规则数量...\n")

    # 检查dataset目录是否存在
    if not os.path.exists("dataset"):
        print("❌ 错误: dataset目录不存在")
        print("请确保在项目根目录下运行此脚本")
        return

    # 统计规则数量
    results = count_siem_rules()

    # 保存结果到文件
    save_results_to_file(results)

    # 生成JSON格式的详细报告
    import json

    json_file = "rule_count_report.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"📄 详细报告已保存到: {json_file}")


if __name__ == "__main__":
    main()
