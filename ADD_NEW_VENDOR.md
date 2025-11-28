# Adding a New SIEM Vendor Guide

This guide will help you add support for a new SIEM vendor to ARuleCon. Follow these steps to integrate a new SIEM system.

## Prerequisites

- All dependencies installed (`pip install -r requirements.txt`)
- OpenAI API key configured

## Step-by-Step Instructions

### Step 1: Prepare Documentation

1. **Find the SIEM vendor's official documentation**

   - Look for official documentation PDFs or documentation files
   - Focus on query language syntax, functions, operators, and best practices
   - Examples: Search Reference Manual, Query Language Guide, API Documentation

2. **Place documentation in the correct directory**

   ```
   dataset/documentations/
   └── {Vendor Name}/
       ├── doc1.pdf
       ├── doc2.pdf
       └── ...
   ```

   **Example:**

   ```
   dataset/documentations/
   └── Elastic Security/
       ├── Elasticsearch Query DSL Guide.pdf
       ├── Kibana Query Language Reference.pdf
       └── ...
   ```

   **Note:** The folder name should match exactly the vendor name you'll use in the configuration (case-sensitive).

### Step 2: Build Vector Database

1. **Run the vector database build script**

   ```bash
   cd script
   python build_vector_db.py
   ```

2. **Verify the build was successful**

   - Check that a new folder appears in `vector_db/` directory:
     ```
     vector_db/
     └── {Vendor Name}/
         └── chroma.sqlite3
     ```
   - The script will automatically:
     - Process all PDF files in `dataset/documentations/{Vendor Name}/`
     - Create intelligent chunks from the documentation
     - Build a ChromaDB collection named `siem_{vendor_name_lowercase}`
     - Store the vector database in `vector_db/{Vendor Name}/`

3. **Check the processing summary**
   - The script will output a summary showing:
     - Number of files processed
     - Number of chunks created
     - SIEM breakdown

### Step 3: Add Prompts Configuration

Edit `src/core/prompts.py` and add entries for your new vendor in two dictionaries:

#### 3.1 Add to `SIEM_CONTENT_GUIDANCE`

This dictionary contains the documentation table of contents structure. It helps the RAG system retrieve relevant documentation sections.

**Location:** `src/core/prompts.py` (around line 8)

**Format:**

```python
SIEM_CONTENT_GUIDANCE = {
    # ... existing entries ...
    "{Vendor Name}": """
    Introduction
    Getting Started
    Query Language Basics
    Syntax Reference
    Functions
    Operators
    Best Practices
    Examples
    ...
    """,
}
```

**Example for Elastic Security:**

```python
SIEM_CONTENT_GUIDANCE = {
    # ... existing entries ...
    "Elastic Security": """
    Introduction
    Elasticsearch Query DSL
    Query and filter context
    Compound queries
    Full text queries
    Term-level queries
    Joining queries
    Geo queries
    Specialized queries
    Aggregations
    Bucket aggregations
    Metrics aggregations
    Pipeline aggregations
    Scripting
    Mapping
    Analysis
    """,
}
```

**Tips:**

- Extract the actual table of contents from the documentation
- Include major sections and subsections
- Keep it organized and hierarchical
- Use actual section titles from the documentation

#### 3.2 Add to `SIEM_KEYWORD_GUIDANCE`

This dictionary contains search keywords for RAG queries. It helps improve retrieval accuracy.

**Location:** `src/core/prompts.py` (around line 361)

**Format:**

```python
SIEM_KEYWORD_GUIDANCE = {
    # ... existing entries ...
    "{Vendor Name}": """
    Guidance for RAG search keywords:

    1. Query basics: syntax, usage, manual, query language
    2. Core concepts: [list key concepts]
    3. Functions: [list function categories and names]
    4. Operators: [list operators]
    5. Data types: [list data types]
    6. Best practices: [list best practice topics]
    ...
    """,
}
```

**Example for Elastic Security:**

```python
SIEM_KEYWORD_GUIDANCE = {
    # ... existing entries ...
    "Elastic Security": """
    Guidance for RAG search keywords:

    1. Query DSL basics: Elasticsearch Query DSL, query syntax, filter context, query context
    2. Query types: match, match_all, match_phrase, multi_match, term, terms, range, exists, bool, must, should, must_not
    3. Aggregations: bucket aggregations, metrics aggregations, terms aggregation, date_histogram, avg, sum, max, min, cardinality
    4. Scripting: painless script, scripted fields, script queries
    5. Mapping: field mapping, data types, text, keyword, date, numeric types
    6. Analysis: analyzers, tokenizers, filters, custom analyzers
    7. Best practices: query performance, indexing optimization, search optimization
    """,
}
```

**Tips:**

- Include common query keywords and function names
- Add syntax elements and operators
- Include best practice topics
- Focus on terms users would search for when writing queries

### Step 4: Update Configuration Files

#### 4.1 Update `settings.py`

Edit `settings.py` and add your new vendor to the following dictionaries:

**4.1.1 Add to `SIEM_RULE_PATHS`** (around line 16)

```python
SIEM_RULE_PATHS = {
    # ... existing entries ...
    "{Vendor Name}": {
        "rules": RULES_DIR / "{Vendor Name}" / "rules",
        # Add other path types as needed
    },
}
```

**Example:**

```python
SIEM_RULE_PATHS = {
    # ... existing entries ...
    "Elastic Security": {
        "detections": RULES_DIR / "Elastic Security" / "detections",
    },
}
```

**4.1.2 Add to `SIEM_DOC_PATHS`** (around line 36)

```python
SIEM_DOC_PATHS = {
    # ... existing entries ...
    "{Vendor Name}": DOCS_DIR / "{Vendor Name}",
}
```

**Example:**

```python
SIEM_DOC_PATHS = {
    # ... existing entries ...
    "Elastic Security": DOCS_DIR / "Elastic Security",
}
```

**4.1.3 Add to `VECTOR_DB_PATHS`** (around line 45)

```python
VECTOR_DB_PATHS = {
    # ... existing entries ...
    "{Vendor Name}": BASE_DIR / "vector_db" / "{Vendor Name}",
}
```

**Example:**

```python
VECTOR_DB_PATHS = {
    # ... existing entries ...
    "Elastic Security": BASE_DIR / "vector_db" / "Elastic Security",
}
```

**4.1.4 Add to `SIEM_FILE_EXTENSIONS`** (around line 58)

```python
SIEM_FILE_EXTENSIONS = {
    # ... existing entries ...
    "{Vendor Name}": [".json", ".yaml"],  # Add appropriate file extensions
}
```

**Example:**

```python
SIEM_FILE_EXTENSIONS = {
    # ... existing entries ...
    "Elastic Security": [".json", ".yaml"],
}
```

**Note:** `SUPPORTED_SIEM_TYPES` is automatically generated from `SIEM_RULE_PATHS.keys()`, so you don't need to modify it manually.

#### 4.2 Update Script Files (if needed)

If the scripts have hardcoded SIEM lists, you'll need to update them:

**4.2.1 `script/batch_rule_conversion.py`** (around lines 30-35, 312-329)

- Add your vendor to the `supported_siems` list in the `BatchRuleConverter` class
- Add your vendor to the `choices` in argument parsers for `--source` and `--target`

**4.2.2 `script/csv_rule_conversion.py`** (around lines 30-36, 322-354)

- Add your vendor to the `supported_siems` list in the `CSVRuleConverter` class
- Add your vendor to the `choices` in argument parsers for `--source` and `--target`

**4.2.3 `script/build_vector_db.py`** (around lines 364-369, 598-603)

- Add your vendor to any hardcoded SIEM lists if present

**4.2.4 `script/test_vector_db_structure.py`** (around lines 33-38, 112-117)

- Add your vendor to test SIEM lists if present

### Step 5: Verify the Integration

1. **Test vector database access**

   ```bash
   cd script
   python test_vector_db_structure.py
   ```

   - Verify your new vendor appears in the collection list
   - Check that queries work correctly

2. **Test rule conversion** (if you have sample rules)

   ```bash
   # Test conversion to your new vendor
   python script/batch_rule_conversion.py --source Splunk --target "{Vendor Name}" --num-rules 1

   # Test conversion from your new vendor
   python script/batch_rule_conversion.py --source "{Vendor Name}" --target "Microsoft Sentinel" --num-rules 1
   ```

3. **Test CSV conversion**

   ```bash
   python script/csv_rule_conversion.py \
     --csv your_test_file.csv \
     --column rule_content \
     --source "{Vendor Name}" \
     --target "Microsoft Sentinel"
   ```

4. **Test web interface**
   ```bash
   streamlit run app.py
   ```
   - Navigate to the rule conversion page
   - Verify your new vendor appears in the source/target dropdowns
   - Test a simple conversion

## Complete Example: Adding "Elastic Security"

Here's a complete example of adding Elastic Security as a new vendor:

### Step 1: Documentation

```
dataset/documentations/
└── Elastic Security/
    ├── Elasticsearch Query DSL Guide.pdf
    └── Kibana Query Language Reference.pdf
```

### Step 2: Build Vector DB

```bash
cd script
python build_vector_db.py
# Verify: vector_db/Elastic Security/ should be created
```

### Step 3: Update `src/core/prompts.py`

Add to `SIEM_CONTENT_GUIDANCE`:

```python
"Elastic Security": """
Introduction
Elasticsearch Query DSL
Query and filter context
Compound queries
Full text queries
Term-level queries
Joining queries
Geo queries
Specialized queries
Aggregations
Bucket aggregations
Metrics aggregations
Pipeline aggregations
Scripting
Mapping
Analysis
""",
```

Add to `SIEM_KEYWORD_GUIDANCE`:

```python
"Elastic Security": """
Guidance for RAG search keywords:

1. Query DSL basics: Elasticsearch Query DSL, query syntax, filter context, query context
2. Query types: match, match_all, match_phrase, multi_match, term, terms, range, exists, bool, must, should, must_not
3. Aggregations: bucket aggregations, metrics aggregations, terms aggregation, date_histogram, avg, sum, max, min, cardinality
4. Scripting: painless script, scripted fields, script queries
5. Mapping: field mapping, data types, text, keyword, date, numeric types
6. Analysis: analyzers, tokenizers, filters, custom analyzers
7. Best practices: query performance, indexing optimization, search optimization
""",
```

### Step 4: Update `settings.py`

```python
SIEM_RULE_PATHS = {
    # ... existing ...
    "Elastic Security": {
        "detections": RULES_DIR / "Elastic Security" / "detections",
    },
}

SIEM_DOC_PATHS = {
    # ... existing ...
    "Elastic Security": DOCS_DIR / "Elastic Security",
}

VECTOR_DB_PATHS = {
    # ... existing ...
    "Elastic Security": BASE_DIR / "vector_db" / "Elastic Security",
}

SIEM_FILE_EXTENSIONS = {
    # ... existing ...
    "Elastic Security": [".json", ".yaml"],
}
```

### Step 5: Update Script Files

Add "Elastic Security" to all hardcoded SIEM lists in:

- `script/batch_rule_conversion.py`
- `script/csv_rule_conversion.py`
- `script/build_vector_db.py` (if needed)
- `script/test_vector_db_structure.py` (if needed)

## Troubleshooting

### Issue: Vector database not created

- **Check:** Ensure PDF files are in `dataset/documentations/{Vendor Name}/`
- **Check:** Verify the folder name matches exactly (case-sensitive)
- **Check:** Review the build script output for errors

### Issue: Vendor not appearing in dropdowns

- **Check:** Verify `settings.py` has all required entries
- **Check:** Ensure vendor name is consistent across all files
- **Check:** Restart the Streamlit app after changes

### Issue: RAG queries not working

- **Check:** Verify `SIEM_CONTENT_GUIDANCE` and `SIEM_KEYWORD_GUIDANCE` are properly formatted
- **Check:** Ensure vector database was built successfully
- **Check:** Test with `script/test_vector_db_structure.py`

### Issue: Conversion errors

- **Check:** Verify the vendor name is correctly added to all script files
- **Check:** Ensure file extensions are correct in `SIEM_FILE_EXTENSIONS`
- **Check:** Review error messages for specific issues

## Additional Notes

- **Vendor Name Consistency:** Always use the exact same vendor name (case-sensitive) across all configuration files
- **Documentation Quality:** Better documentation leads to better RAG performance. Use official, comprehensive documentation when possible
- **Testing:** Always test with a small number of rules first before processing large batches
- **File Extensions:** Make sure to add all file extensions used by the vendor's rule format

## Need Help?

If you encounter issues or have questions:

1. Check the existing vendor configurations as examples
2. Review the error messages carefully
3. Verify all file paths and names are correct
4. Open an issue on GitHub with details about the problem

---

**Happy integrating! 🚀**
