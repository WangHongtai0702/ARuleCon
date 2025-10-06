# 批量规则转换工具

这个工具用于批量转换不同 SIEM 系统之间的安全规则，支持完整的转换流程：IR 生成 → 直接转换 → 语法优化 → 语义优化。

## 功能特性

- 🎯 **多 SIEM 支持**：支持 Splunk、Microsoft Sentinel、Google Chronicle、IBM QRadar、RSA NetWitness
- 🔄 **完整转换流程**：IR 生成 → 直接转换 → 语法优化 → 语义优化
- 📊 **批量处理**：支持指定转换规则数量
- 💾 **结果保存**：自动保存到 result 文件夹，包含完整的转换过程
- 📈 **进度跟踪**：实时显示转换进度和结果统计

## 使用方法

### 1. 命令行使用

```bash
# 查看帮助
python script/batch_rule_conversion.py --help

# 列出可用的SIEM类型
python script/batch_rule_conversion.py --list-siems

# 查看指定SIEM的规则数量
python script/batch_rule_conversion.py --count Splunk

# 转换规则：Splunk -> Microsoft Sentinel (10个规则)
python script/batch_rule_conversion.py --source Splunk --target "Microsoft Sentinel" --num-rules 10

# 转换规则：IBM QRadar -> Google Chronicle (5个规则)
python script/batch_rule_conversion.py --source "IBM QRadar" --target "Google Chronicle" --num-rules 5

# 指定输出目录
python script/batch_rule_conversion.py --source Splunk --target "Microsoft Sentinel" --num-rules 20 --output-dir custom_result
```

### 2. 运行示例

```bash
# 运行示例转换
python script/example_conversion.py
```

## 输出格式

转换结果保存在`result`文件夹中，文件名格式：`{source_type}_to_{target_type}_{timestamp}.json`

### 输出文件结构

```json
{
  "conversion_summary": {
    "source_type": "Splunk",
    "target_type": "Microsoft Sentinel",
    "total_rules": 10,
    "successful_conversions": 8,
    "failed_conversions": 2,
    "conversion_timestamp": "2024-01-15T10:30:00"
  },
  "conversion_results": [
    {
      "source_rule": {
        "rule_name": "Detect Suspicious Activity",
        "rule_content": "index=security | search ...",
        "search_query": "index=security | search ...",
        "description": "Detects suspicious activities",
        "author": "Security Team",
        "file_path": "/path/to/rule.yml",
        "file_type": ".yml",
        "tags": ["security", "detection"],
        "metadata": {}
      },
      "conversion_info": {
        "source_type": "Splunk",
        "target_type": "Microsoft Sentinel",
        "timestamp": "2024-01-15T10:30:00"
      },
      "ir_generation": {
        "ir_content": "rule SuspiciousActivity { ... }",
        "success": true,
        "metadata": {}
      },
      "direct_conversion": {
        "converted_rule": "let SuspiciousActivity = () => { ... }",
        "success": true,
        "metadata": {}
      },
      "syntax_optimization": {
        "optimized_rule": "let SuspiciousActivity = () => { ... }",
        "optimization_suggestions": ["优化了查询性能"],
        "success": true,
        "metadata": {}
      },
      "semantic_optimization": {
        "optimized_rule": "let SuspiciousActivity = () => { ... }",
        "optimization_suggestions": ["改进了检测逻辑"],
        "equivalence_score": 0.95,
        "success": true,
        "metadata": {}
      },
      "errors": []
    }
  ]
}
```

## 支持的转换类型

| 源类型             | 目标类型           | 状态 |
| ------------------ | ------------------ | ---- |
| Splunk             | Microsoft Sentinel | ✅   |
| Splunk             | Google Chronicle   | ✅   |
| Splunk             | IBM QRadar         | ✅   |
| Splunk             | RSA NetWitness     | ✅   |
| Microsoft Sentinel | Splunk             | ✅   |
| Microsoft Sentinel | Google Chronicle   | ✅   |
| Microsoft Sentinel | IBM QRadar         | ✅   |
| Microsoft Sentinel | RSA NetWitness     | ✅   |
| Google Chronicle   | Splunk             | ✅   |
| Google Chronicle   | Microsoft Sentinel | ✅   |
| Google Chronicle   | IBM QRadar         | ✅   |
| Google Chronicle   | RSA NetWitness     | ✅   |
| IBM QRadar         | Splunk             | ✅   |
| IBM QRadar         | Microsoft Sentinel | ✅   |
| IBM QRadar         | Google Chronicle   | ✅   |
| IBM QRadar         | RSA NetWitness     | ✅   |
| RSA NetWitness     | Splunk             | ✅   |
| RSA NetWitness     | Microsoft Sentinel | ✅   |
| RSA NetWitness     | Google Chronicle   | ✅   |
| RSA NetWitness     | IBM QRadar         | ✅   |

## 注意事项

1. **规则数量限制**：如果请求的规则数量超过可用数量，会自动调整到最大可用数量
2. **转换时间**：转换时间取决于规则复杂度和数量，建议先用少量规则测试
3. **错误处理**：转换失败的规则会在结果中标记，不会影响其他规则的转换
4. **输出目录**：确保有足够的磁盘空间保存转换结果

## 故障排除

### 常见问题

1. **导入错误**：确保在项目根目录运行脚本
2. **规则加载失败**：检查 dataset 目录是否存在且包含规则文件
3. **转换失败**：查看错误信息，通常是规则格式不支持或 LLM 服务问题

### 调试模式

```bash
# 使用少量规则测试
python script/batch_rule_conversion.py --source Splunk --target "Microsoft Sentinel" --num-rules 1
```
