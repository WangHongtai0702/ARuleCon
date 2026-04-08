# Batch Rule Conversion Tool

This tool is used for batch conversion of security rules between different SIEM systems, supporting a complete conversion workflow: IR generation → Direct conversion → Syntax optimization → Semantic optimization.

## Features

- 🎯 **Multi-SIEM Support**: Supports Splunk, Microsoft Sentinel, Google Chronicle, IBM QRadar, RSA NetWitness
- 🔄 **Complete Conversion Workflow**: IR generation → Direct conversion → Syntax optimization → Semantic optimization
- 📊 **Batch Processing**: Supports specifying the number of rules to convert
- 💾 **Result Saving**: Automatically saves to the result folder, including the complete conversion process
- 📈 **Progress Tracking**: Real-time display of conversion progress and result statistics
- 📄 **CSV Support**: Supports reading rules from CSV files for batch conversion

## Usage

### 1. Command Line Usage

```bash
# View help
python script/batch_rule_conversion.py --help

# List available SIEM types
python script/batch_rule_conversion.py --list-siems

# View rule count for specified SIEM
python script/batch_rule_conversion.py --count Splunk

# Convert rules: Splunk -> Microsoft Sentinel (10 rules)
python script/batch_rule_conversion.py --source Splunk --target "Microsoft Sentinel" --num-rules 10

# Convert rules: IBM QRadar -> Google Chronicle (5 rules)
python script/batch_rule_conversion.py --source "IBM QRadar" --target "Google Chronicle" --num-rules 5

# Specify output directory
python script/batch_rule_conversion.py --source Splunk --target "Microsoft Sentinel" --num-rules 20 --output-dir custom_result
```

### 2. CSV Input Conversion

```bash
# Read rules from CSV file for conversion
python script/csv_rule_conversion.py \
  --csv input_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Microsoft Sentinel" \
  --model gpt-4o-mini

# Specify output directory
python script/csv_rule_conversion.py \
  --csv input_rules.csv \
  --column rule_content \
  --source "Google Chronicle" \
  --target Splunk \
  --output-dir result/custom_output
```

**CSV File Example Format:**

```csv
name,rule_content,description
Suspicious Login,index=security | search user=admin,Detects suspicious admin logins
Port Scan,index=network | stats count by src_ip,Detects port scanning activities
```

**CSV Conversion Parameter Description:**

- `--csv` / `-f`: CSV file path (required)
- `--column` / `-c`: Column name containing rules (required)
- `--source` / `-s`: Source rule type (required)
- `--target` / `-t`: Target rule type (required)
- `--model` / `-m`: Model to use (optional, default: gpt-4o-mini)
- `--csv-output-column`: Custom name for the conversion result column

## Output Format

Conversion results are saved directly in the same directory as the original CSV file, with filename format: `{original_filename}_converted_{timestamp}.csv`

### Output File Structure

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
        "optimization_suggestions": ["Optimized query performance"],
        "success": true,
        "metadata": {}
      },
      "semantic_optimization": {
        "optimized_rule": "let SuspiciousActivity = () => { ... }",
        "optimization_suggestions": ["Improved detection logic"],
        "equivalence_score": 0.95,
        "success": true,
        "metadata": {}
      },
      "errors": []
    }
  ]
}
```

## Supported Conversion Types

| Source Type        | Target Type        | Status |
| ------------------ | ------------------ | ------ |
| Splunk             | Microsoft Sentinel | ✅     |
| Splunk             | Google Chronicle   | ✅     |
| Splunk             | IBM QRadar         | ✅     |
| Splunk             | RSA NetWitness     | ✅     |
| Microsoft Sentinel | Splunk             | ✅     |
| Microsoft Sentinel | Google Chronicle   | ✅     |
| Microsoft Sentinel | IBM QRadar         | ✅     |
| Microsoft Sentinel | RSA NetWitness     | ✅     |
| Google Chronicle   | Splunk             | ✅     |
| Google Chronicle   | Microsoft Sentinel | ✅     |
| Google Chronicle   | IBM QRadar         | ✅     |
| Google Chronicle   | RSA NetWitness     | ✅     |
| IBM QRadar         | Splunk             | ✅     |
| IBM QRadar         | Microsoft Sentinel | ✅     |
| IBM QRadar         | Google Chronicle   | ✅     |
| IBM QRadar         | RSA NetWitness     | ✅     |
| RSA NetWitness     | Splunk             | ✅     |
| RSA NetWitness     | Microsoft Sentinel | ✅     |
| RSA NetWitness     | Google Chronicle   | ✅     |
| RSA NetWitness     | IBM QRadar         | ✅     |

## Notes

1. **Rule Count Limit**: If the requested number of rules exceeds the available count, it will automatically adjust to the maximum available count
2. **Conversion Time**: Conversion time depends on rule complexity and quantity, it's recommended to test with a small number of rules first
3. **Error Handling**: Failed rule conversions will be marked in the results and will not affect other rule conversions
4. **Output Directory**: Ensure sufficient disk space to save conversion results

## Troubleshooting

### Common Issues

1. **Import Error**: Ensure the script is run from the project root directory
2. **Rule Loading Failure**: Check if the dataset directory exists and contains rule files
3. **Conversion Failure**: Check error messages, usually due to unsupported rule format or LLM service issues

### Debug Mode

```bash
# Test with a small number of rules
python script/batch_rule_conversion.py --source Splunk --target "Microsoft Sentinel" --num-rules 1
```

### CSV Conversion Example

```bash
# Test with example CSV file
python script/csv_rule_conversion.py \
  --csv script/example_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Microsoft Sentinel"
```

## CSV Input Conversion Detailed Instructions

The `csv_rule_conversion.py` script allows you to read rules from CSV files and perform batch conversion. This tool is particularly suitable for the following scenarios:

1. **Custom Rule Input**: You have your own rule list that needs conversion
2. **External Data Sources**: Need to convert rules from external sources to target SIEM format
3. **Flexible Configuration**: Can specify different models and parameters for each conversion

### CSV File Requirements

- **Format**: Standard CSV format (comma-separated)
- **Required Column**: Column containing rules (specified via `--column`)
- **Optional**: Other columns will be preserved in the results for subsequent analysis
- **Auto-naming**: If the CSV has columns like `name`, `title`, `rule_name`, etc., they will automatically be used as rule names

### Output Files

CSV conversion generates converted CSV files:

**Converted CSV File**: Contains original data and converted rules, saved in the same directory as the original file

- Filename format: `{original_filename}_converted_{timestamp}.csv`
- New column: `converted_rule_{target_type}`, containing the converted rules

**CSV Output Example:**

Original CSV:

```csv
name,rule_content,description
Suspicious Login,index=security | search user=admin,Detects suspicious admin logins
```

Converted CSV:

```csv
name,rule_content,description,converted_rule_Microsoft Sentinel
Suspicious Login,index=security | search user=admin,Detects suspicious admin logins,let SuspiciousLogin = () {...}
```
