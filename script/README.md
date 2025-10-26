# 批量规则转换工具

这个工具用于批量转换不同 SIEM 系统之间的安全规则，支持完整的转换流程：IR 生成 → 直接转换 → 语法优化 → 语义优化。

## 功能特性

- 🎯 **多 SIEM 支持**：支持 Splunk、Microsoft Sentinel、Google Chronicle、IBM QRadar、RSA NetWitness
- 🔄 **完整转换流程**：IR 生成 → 直接转换 → 语法优化 → 语义优化
- 📊 **批量处理**：支持指定转换规则数量
- 💾 **结果保存**：自动保存到 result 文件夹，包含完整的转换过程
- 📈 **进度跟踪**：实时显示转换进度和结果统计
- 📄 **CSV 支持**：支持从 CSV 文件读取规则进行批量转换

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

### 2. CSV 输入转换

```bash
# 从 CSV 文件读取规则进行转换
python script/csv_rule_conversion.py \
  --csv input_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Microsoft Sentinel" \
  --model gpt-4o-mini

# 指定输出目录
python script/csv_rule_conversion.py \
  --csv input_rules.csv \
  --column rule_content \
  --source "Google Chronicle" \
  --target Splunk \
  --output-dir result/custom_output
```

**CSV 文件示例格式：**

```csv
name,rule_content,description
Suspicious Login,index=security | search user=admin,Detects suspicious admin logins
Port Scan,index=network | stats count by src_ip,Detects port scanning activities
```

**CSV 转换参数说明：**

- `--csv` / `-f`: CSV 文件路径（必需）
- `--column` / `-c`: 包含规则的列名称（必需）
- `--source` / `-s`: 源规则类型（必需）
- `--target` / `-t`: 目标规则类型（必需）
- `--model` / `-m`: 使用的模型（可选，默认：gpt-4o-mini）
- `--csv-output-column`: 自定义转换结果列的名称

## 输出格式

转换结果直接保存在与原 CSV 文件同目录，文件名格式：`{原文件名}_converted_{时间戳}.csv`

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

### CSV 转换示例

```bash
# 使用示例 CSV 文件测试
python script/csv_rule_conversion.py \
  --csv script/example_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Microsoft Sentinel"
```

## CSV 输入转换详细说明

`csv_rule_conversion.py` 脚本允许您从 CSV 文件读取规则并进行批量转换。这个工具特别适用于以下场景：

1. **自定义规则输入**：您有自己的规则列表需要转换
2. **外部数据源**：需要将外部来源的规则转换为目标 SIEM 格式
3. **灵活配置**：可以为每个转换指定不同的模型和参数

### CSV 文件要求

- **格式**：标准 CSV 格式（逗号分隔）
- **必需列**：包含规则的列（通过 `--column` 指定）
- **可选项**：其他列会被保留在结果中，方便后续分析
- **自动命名**：如果 CSV 有 `name`、`title`、`rule_name` 等列，会自动作为规则名称

### 输出文件

CSV 转换会生成转换后的 CSV 文件：

**转换后的 CSV 文件**：包含原始数据和转换后的规则，保存在与原文件同目录

- 文件名格式：`{原文件名}_converted_{时间戳}.csv`
- 新增列：`converted_rule_{目标类型}`，包含转换后的规则

**CSV 输出示例：**

原 CSV：

```csv
name,rule_content,description
Suspicious Login,index=security | search user=admin,Detects suspicious admin logins
```

转换后的 CSV：

```csv
name,rule_content,description,converted_rule_Microsoft Sentinel
Suspicious Login,index=security | search user=admin,Detects suspicious admin logins,let SuspiciousLogin = () {...}
```
