# Evaluation Scripts

This directory contains evaluation scripts for assessing the quality of rule conversion results. Two evaluation methods are provided:

1. **Embedding Similarity Evaluation** (`embedding_similarity.py`) - Uses OpenAI embeddings to calculate semantic similarity
2. **LLM Judge Evaluation** (`llm_judge_evaluatior.py`) - Uses LLM as a judge to evaluate semantic similarity across multiple dimensions

## Overview

### Embedding Similarity Evaluation

This method uses OpenAI's embedding models to convert rules into vector representations and calculates cosine similarity between source and target rules. It provides a quick, automated way to measure semantic similarity.

**Key Features:**

- Fast evaluation using embedding models
- Cosine similarity scores (0-1 range)
- Evaluates three conversion stages: direct conversion, syntax optimization, semantic optimization
- Caching mechanism to avoid redundant API calls

### LLM Judge Evaluation

This method uses a Large Language Model (LLM) as an expert judge to evaluate rule conversion quality across six semantic dimensions. It provides detailed, human-like evaluation with reasoning.

**Key Features:**

- Multi-dimensional evaluation (6 semantic dimensions)
- Detailed reasoning and analysis for each dimension
- Strict evaluation criteria
- Evaluates three conversion stages: direct conversion, syntax optimization, semantic optimization
- Score range: 0-10 for each dimension

## Prerequisites

- Python 3.8+
- OpenAI API key configured (set in `.env` file or environment variable)
- Required packages: `openai`, `numpy`, `pandas`, `scikit-learn`, `tqdm`, `python-dotenv`

## Embedding Similarity Evaluation

### Usage

```bash
cd evaluation
python embedding_similarity.py [OPTIONS]
```

### Command Line Options

| Option         | Description                             | Default                  |
| -------------- | --------------------------------------- | ------------------------ |
| `--result-dir` | Directory containing conversion results | `result`                 |
| `--model`      | OpenAI embedding model to use           | `text-embedding-3-small` |
| `--output-dir` | Output directory for results            | `evaluation`             |
| `--verbose`    | Enable verbose logging                  | False                    |

### Example

```bash
# Basic usage
python embedding_similarity.py

# Specify custom result directory
python embedding_similarity.py --result-dir custom_result

# Use a different embedding model
python embedding_similarity.py --model text-embedding-3-large

# Enable verbose output
python embedding_similarity.py --verbose
```

### Output Files

1. **`embedding_similarity_results.json`** - Detailed results for each rule

   - Contains similarity scores for all three conversion stages
   - Includes source and target rule content
   - Metadata (rule name, file path, timestamp)

2. **`embedding_similarity_summary.json`** - Summary statistics
   - Overall statistics by conversion type
   - Mean, std, min, max similarity scores
   - Breakdown by conversion stage

### Output Format

**Results File Structure:**

```json
[
  {
    "source_rule_type": "Splunk",
    "target_rule_type": "Microsoft Sentinel",
    "rule_name": "SuspiciousLogin",
    "source_rule": "index=security | search user=admin",
    "direct_conversion_rule": "let SuspiciousLogin = () => {...}",
    "syntax_optimization_rule": "let SuspiciousLogin = () => {...}",
    "semantic_optimization_rule": "let SuspiciousLogin = () => {...}",
    "direct_conversion_similarity": 0.85,
    "syntax_optimization_similarity": 0.87,
    "semantic_optimization_similarity": 0.89,
    "file_path": "result/Splunk/Microsoft Sentinel/...",
    "evaluation_timestamp": "2024-01-15T10:30:00"
  }
]
```

**Summary File Structure:**

```json
{
  "total_rules_evaluated": 100,
  "conversion_types": 5,
  "conversion_type_summaries": {
    "Splunk -> Microsoft Sentinel": {
      "total_rules": 20,
      "direct_conversion": {
        "count": 20,
        "mean_similarity": 0.85,
        "std_similarity": 0.10,
        "min_similarity": 0.65,
        "max_similarity": 0.95
      },
      "syntax_optimization": {...},
      "semantic_optimization": {...}
    }
  }
}
```

## LLM Judge Evaluation

### Usage

```bash
cd evaluation
python llm_judge_evaluatior.py [OPTIONS]
```

### Command Line Options

| Option                      | Description                             | Default       |
| --------------------------- | --------------------------------------- | ------------- |
| `--result-dir`              | Directory containing conversion results | `result`      |
| `--output-dir`              | Output directory for results            | `evaluation`  |
| `--model`                   | LLM model to use for evaluation         | `gpt-4o-mini` |
| `--max-results`             | Maximum number of results to evaluate   | None (all)    |
| `--max-per-conversion-type` | Max results per conversion type         | 10            |
| `--verbose`                 | Enable verbose logging                  | False         |

### Example

```bash
# Basic usage (evaluates up to 10 rules per conversion type)
python llm_judge_evaluatior.py

# Evaluate all results
python llm_judge_evaluatior.py --max-per-conversion-type 100

# Limit total number of results
python llm_judge_evaluatior.py --max-results 50

# Use a different model
python llm_judge_evaluatior.py --model gpt-4o

# Custom result directory
python llm_judge_evaluatior.py --result-dir custom_result
```

### Evaluation Dimensions

The LLM judge evaluates rules across six semantic dimensions (SF1-SF6):

1. **SF1: Event Scope & Field Mapping** (事件范围 & 字段映射)

   - Checks if rules target the same log sources/tables
   - Verifies field mappings are semantically identical
   - Evaluates data source compatibility

2. **SF2: Predicates & Boolean Logic** (谓词 & 布尔逻辑)

   - Verifies filtering conditions are equivalent
   - Ensures boolean logic (AND, OR, NOT) is identical
   - Checks operator consistency

3. **SF3: Time Window** (时间窗口)

   - Ensures time windows are exactly the same
   - Verifies time-based aggregation logic
   - Checks sliding vs fixed window implementations

4. **SF4: Aggregation & Thresholds** (聚合 & 阈值)

   - Verifies statistical functions are identical
   - Ensures threshold values match exactly
   - Checks aggregation method consistency

5. **SF5: Correlation/Joins** (关联/连接)

   - Verifies join keys are identical
   - Checks time constraints for correlations
   - Evaluates correlation logic equivalence

6. **SF6: Alert Triggering & Output** (告警触发 & 输出)
   - Verifies trigger conditions are equivalent
   - Ensures output format and content match
   - Checks alert metadata consistency

### Scoring Criteria

Each dimension is scored from 0-10:

- **10 points**: Perfect match - Rules are semantically identical
- **8-9 points**: Excellent - Very minor differences
- **6-7 points**: Good - Some differences but core logic preserved
- **4-5 points**: Fair - Significant differences but basic functionality maintained
- **2-3 points**: Poor - Major differences affecting detection effectiveness
- **0-1 points**: Fail - Rules are fundamentally different

### Output Files

1. **`llm_judge_results.json`** - Detailed results for each rule

   - Contains scores for all six dimensions
   - Includes reasoning and detailed analysis
   - Scores for all three conversion stages

2. **`llm_judge_summary.json`** - Summary statistics
   - Overall statistics by conversion type
   - Dimension-level statistics
   - Breakdown by conversion stage

### Output Format

**Results File Structure:**

```json
[
  {
    "source_rule_type": "Splunk",
    "target_rule_type": "Microsoft Sentinel",
    "rule_name": "SuspiciousLogin",
    "source_rule": "index=security | search user=admin",
    "direct_converted_rule": "let SuspiciousLogin = () => {...}",
    "syntax_optimized_rule": "let SuspiciousLogin = () => {...}",
    "semantic_optimized_rule": "let SuspiciousLogin = () => {...}",
    "direct_conversion_scores": {
      "SF1": {
        "score": 8.5,
        "reasoning": "Field mappings are mostly equivalent...",
        "details": "Source uses 'user' field, target uses 'UserName'..."
      },
      "SF2": {...},
      "SF3": {...},
      "SF4": {...},
      "SF5": {...},
      "SF6": {...}
    },
    "syntax_optimization_scores": {...},
    "semantic_optimization_scores": {...},
    "direct_conversion_overall": 7.8,
    "syntax_optimization_overall": 8.2,
    "semantic_optimization_overall": 8.5,
    "file_path": "result/Splunk/Microsoft Sentinel/...",
    "evaluation_timestamp": "2024-01-15T10:30:00",
    "llm_model": "gpt-4o-mini"
  }
]
```

**Summary File Structure:**

```json
{
  "total_rules_evaluated": 50,
  "conversion_types": 5,
  "dimension_summaries": {
    "SF1": {
      "dimension_name": "事件范围 & 字段映射",
      "mean_score": 7.5,
      "min_score": 4.0,
      "max_score": 9.5
    },
    ...
  },
  "conversion_type_summaries": {
    "Splunk -> Microsoft Sentinel": {
      "total_rules": 10,
      "direct_conversion": {
        "overall": {
          "mean_score": 7.8,
          "min_score": 5.5,
          "max_score": 9.2
        },
        "dimensions": {
          "SF1": {"mean_score": 8.0, "min_score": 6.0, "max_score": 9.5},
          ...
        }
      },
      "syntax_optimization": {...},
      "semantic_optimization": {...}
    }
  }
}
```

## Comparison of Methods

| Aspect               | Embedding Similarity         | LLM Judge                      |
| -------------------- | ---------------------------- | ------------------------------ |
| **Speed**            | Fast (batch processing)      | Slower (sequential LLM calls)  |
| **Cost**             | Lower (embedding API)        | Higher (chat completion API)   |
| **Granularity**      | Single similarity score      | 6 dimension scores + reasoning |
| **Interpretability** | Low (just a number)          | High (detailed reasoning)      |
| **Use Case**         | Quick batch evaluation       | Detailed quality assessment    |
| **Accuracy**         | Good for semantic similarity | Better for nuanced evaluation  |

## Best Practices

### When to Use Embedding Similarity

- Quick evaluation of large batches of rules
- Initial screening to identify problematic conversions
- Cost-effective evaluation when detailed analysis isn't needed
- Comparing similarity trends across conversion stages

### When to Use LLM Judge

- Detailed quality assessment for critical rules
- Understanding specific issues in rule conversion
- Getting actionable feedback for improvement
- Research and development of conversion algorithms

### Recommended Workflow

1. **Initial Screening**: Use embedding similarity to evaluate all conversion results
2. **Detailed Analysis**: Use LLM judge on a subset of rules (e.g., low similarity scores or critical rules)
3. **Iterative Improvement**: Use LLM judge feedback to improve conversion algorithms

## Troubleshooting

### Common Issues

**Issue: OpenAI API key not found**

```
Error: OpenAI API key not found
```

**Solution**:

- Set `OPENAI_API_KEY` in `.env` file
- Or set as environment variable: `export OPENAI_API_KEY=your_key`

**Issue: No conversion results found**

```
Warning: No conversion results found
```

**Solution**:

- Check that `result` directory exists
- Verify conversion results are in JSON format
- Check the `--result-dir` path is correct

**Issue: LLM evaluation fails**

```
Error: LLM evaluation failed
```

**Solution**:

- Check API key and quota
- Try a different model
- Check network connectivity
- Review error logs for specific issues

**Issue: Memory errors with large datasets**

```
Error: MemoryError
```

**Solution**:

- Use `--max-results` to limit evaluation
- Use `--max-per-conversion-type` to limit per type
- Process in smaller batches

## Performance Considerations

### Embedding Similarity

- **Processing Time**: ~1-2 seconds per rule (with caching)
- **API Cost**: ~$0.0001 per rule (text-embedding-3-small)
- **Scalability**: Can process thousands of rules efficiently

### LLM Judge

- **Processing Time**: ~5-10 seconds per rule
- **API Cost**: ~$0.001-0.01 per rule (gpt-4o-mini)
- **Scalability**: Limited by API rate limits; use `--max-per-conversion-type` for large datasets

## Example Workflow

```bash
# Step 1: Run embedding similarity on all results
python embedding_similarity.py --result-dir result --output-dir evaluation

# Step 2: Review summary to identify low-scoring conversions
cat evaluation/embedding_similarity_summary.json

# Step 3: Run LLM judge on a subset for detailed analysis
python llm_judge_evaluatior.py \
  --result-dir result \
  --output-dir evaluation \
  --max-per-conversion-type 20

# Step 4: Analyze detailed results
cat evaluation/llm_judge_summary.json
```

## Integration with Conversion Pipeline

These evaluation scripts are designed to work with the conversion results generated by:

- `script/batch_rule_conversion.py`
- `script/csv_rule_conversion.py`
- Web interface conversion results

The scripts automatically detect and process all JSON files in the result directory structure:

```
result/
├── Splunk/
│   ├── Microsoft Sentinel/
│   │   ├── rule1.json
│   │   └── rule2.json
│   └── Google Chronicle/
│       └── rule1.json
└── ...
```

## Additional Notes

- Both scripts support caching to avoid redundant API calls
- Results are saved in JSON format for easy analysis
- Summary reports provide statistical insights
- Verbose logging helps debug issues
- Scripts handle missing or invalid data gracefully

## Support

For issues or questions:

1. Check the error messages and logs
2. Verify API key and quota
3. Review the output JSON files for details
4. Open an issue on GitHub with error details

---

**Happy Evaluating! 📊**
