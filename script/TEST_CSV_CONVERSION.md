# CSV Rule Conversion Testing Guide

This document provides instructions for testing the `csv_rule_conversion.py` script using the provided test CSV file.

## Test File

- **Test CSV**: `test_rules.csv`
- **Location**: `script/test_rules.csv`
- **Content**: 15 sample Splunk detection rules with metadata

## Test CSV Structure

The test CSV contains the following columns:

- `rule_name`: Name of the detection rule
- `rule_content`: The actual Splunk search query
- `description`: Description of what the rule detects
- `author`: Author/team responsible for the rule
- `tags`: Tags for categorizing the rule

## Running the Test

### Basic Test - Convert to Microsoft Sentinel

```bash
python script/csv_rule_conversion.py \
  --csv script/test_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Microsoft Sentinel"
```

### Convert to Google Chronicle

```bash
python script/csv_rule_conversion.py \
  --csv script/test_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Google Chronicle"
```

### Convert to IBM QRadar

```bash
python script/csv_rule_conversion.py \
  --csv script/test_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "IBM QRadar"
```

### Using Different Models

```bash
# Use GPT-5-mini
python script/csv_rule_conversion.py \
  --csv script/test_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Microsoft Sentinel" \
  --model gpt-5-mini

# Use GPT-5
python script/csv_rule_conversion.py \
  --csv script/test_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Microsoft Sentinel" \
  --model gpt-5
```

### Custom Output Column Name

```bash
python script/csv_rule_conversion.py \
  --csv script/test_rules.csv \
  --column rule_content \
  --source Splunk \
  --target "Microsoft Sentinel" \
  --csv-output-column sentinel_query
```

## Expected Output

After running the script, you will get:

1. **Converted CSV File**: `test_rules_converted_{timestamp}.csv`

   - Location: Same directory as the input CSV
   - Contains original columns plus a new column with converted rules
   - New column name format: `converted_rule_{target_type}`

2. **Console Output**:
   - Progress information for each rule
   - Conversion statistics
   - Path to the output CSV file

## Example Output CSV Structure

```csv
rule_name,rule_content,description,author,tags,converted_rule_Microsoft Sentinel
Suspicious Login Attempts,index=security | search...,Detects multiple failed login attempts,let SuspiciousLoginAttempts = () => {...}
```

## Testing Tips

1. **Small Batch Test**: First test with a few rules to verify the setup
2. **Check Output**: Verify the converted rules are syntactically correct
3. **Error Handling**: Check that failed conversions are properly marked
4. **Performance**: Monitor conversion time and API usage

## Common Issues

### Issue: Column Not Found

- **Error**: `Column 'rule_content' not found in CSV`
- **Solution**: Check the CSV column name matches the `--column` parameter

### Issue: API Key Not Set

- **Error**: `OpenAI API key not configured`
- **Solution**: Set the `OPENAI_API_KEY` environment variable

### Issue: Empty CSV

- **Error**: `No rules found in CSV`
- **Solution**: Ensure the CSV file has data and the correct column

## Verification Checklist

- [ ] Test file loads correctly
- [ ] Conversions complete without errors
- [ ] Output CSV contains all original columns
- [ ] Output CSV has the new converted rule column
- [ ] Conversion statistics are accurate
- [ ] Failed conversions are handled gracefully

## Next Steps

After successful testing, you can:

1. Use your own CSV files with different rules
2. Test conversions between other SIEM types
3. Integrate the output into your workflow
4. Customize the conversion parameters for your needs
