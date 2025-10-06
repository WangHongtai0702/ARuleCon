"""
Prompts for RuleOptimizer to generate optimization todo lists.
"""

from typing import List

# SIEM-specific content guidance
SIEM_CONTENT_GUIDANCE = {
    "Splunk": """
Introduction
Welcome to the Search Reference
Understanding SPL syntax
How to use this manual
Quick Reference
Splunk Quick Reference Guide
Command quick reference
Commands by category
Command types
Splunk SPL for SQL users
Evaluation Functions
Evaluation functions
Bitwise functions
Comparison and Conditional functions
Conversion functions
Cryptographic functions
Date and Time functions
Informational functions
JSON functions
Mathematical functions
Multivalue eval functions
Statistical eval functions
Text functions
Trig and Hyperbolic functions
Statistical and Charting Functions
Statistical and charting functions
Aggregate functions
Event order functions
Multivalue stats and chart functions
Time functions
Time Format Variables and Modifiers
Date and time format variables
Time modifiers
Search Commands
Full catalog of commands
3rd party custom commands
Internal Commands
About internal commands
collapse
dump
findkeywords
makejson
mcatalog
noop
prjob
redistribute
runshellscript
Search in the CLI
About searches in the CLI
Syntax for searches in the CLI
    """,
    "Microsoft Sentinel": """
General Conventions
Syntax conventions
Comments
Debug KQL inline Python

Best Practices
Best practices for KQL queries
Optimize queries using named expressions

Data Model
Entity types
Entity names
Entity references
Databases
Tables
Columns
Stored functions
Views
External tables
Fact and dimension tables

Data Types
Scalar data types: bool, datetime, decimal, dynamic, guid, int, long, real, string, timespan
Null values

Functions
Function types
User-defined functions
Statistical functions: bartlett_test_fl(), binomial_test_fl(), ks_test_fl(), mann-whitney-u-test-fl(), two_sample_t_test_fl(), wilcoxon_test_fl()
ML & anomaly detection: dbscan_fl(), detect_anomalous_access_cf_fl(), kmeans_fl(), predict_fl(), predict_onnx_fl(), series_* functions
Graph functions: graph_blast_radius_fl(), graph_exposure_perimeter_fl(), graph_node_centrality_fl(), graph_path_discovery_fl()
Visualization functions: plotly_anomaly_fl(), plotly_gauge_fl(), plotly_graph_fl(), plotly_scatter3d_fl()
Time-weighted functions: time_weighted_avg_fl(), time_weighted_val_fl()

Query Statements
Alias statement
Let statement
Pattern statement
Query parameters
Restrict statement
Set statement
Tabular expression statements
Batches

Query Operators
as, count, distinct, extend, project, where, sort, take, top
Join operators: cross-cluster join, broadcast join, time window join
Data parsing: parse, parse-where, parse-kv
Data expansion: mv-apply, mv-expand
Other operators: union, datatable, invoke, lookup, search, serialize, scan

Cross-Database & Results
Cross-cluster and cross-database queries: cluster(), database()
Materialization: materialize(), materialized_view()
Query results cache: stored_query_result()

Operators & Arithmetic
Bitwise binary operators
Datetime/timespan arithmetic
Logical operators
Numerical operators

Scalar Functions
Math: abs(), exp(), log(), pow(), sqrt(), sin(), cos(), tan()
Arrays: array_concat(), array_index_of(), array_slice(), array_sum()
Strings: strlen(), substring(), replace_string(), tolower(), toupper()
Datetime: ago(), datetime_add(), endofmonth(), startofweek()
Conversion: todatetime(), tostring(), toint(), toreal()
Hashing/encoding: hash_md5(), hash_sha256(), base64_encode, gzip, zlib
Parsing: parse_json(), parse_url(), parse_user_agent(), parse_version()

Aggregation Functions
count(), sum(), avg(), min(), max()
Distinct: dcount(), hll(), count_distinct()
Percentiles: percentile(), percentiles(), tdigest()
Statistical: variance(), stdev(), covariance()
Collecting: make_list(), make_set(), make_bag()

Geospatial Functions
Geospatial clustering, joins, visualizations
geo_distance, geo_intersects, geo_union
geo_point_to_h3cell(), geo_polygon_to_s2cells()
geo_line_length(), geo_polygon_area()

Window Functions
next(), prev()
row_number(), row_rank_dense(), row_rank_min()
row_cumsum(), row_window_session()
    """,
    "IBM QRadar": """
Chapter 1. Ariel Query Language in the QRadar interface
Chapter 2. AQL Query structure
   SELECT statement
   WHERE clause
   GROUP BY clause
   HAVING clause
   ORDER BY clause
   LIKE clause
   COUNT function
   Quotation marks
   Sample AQL queries
Chapter 3. Ariel Query Language
AQL operators and functions
   AQL logical and comparison operators
AQL data calculation and formatting functions
BASE64
CONCAT
DATEFORMAT
DOUBLE
LONG
NOW
PARSEDATETIME
PARSETIMESTAMP
REPLACEALL
REPLACEFIRST
STR / STRLEN / STRPOS
SUBSTRING
UPPER / LOWER
UTF8
AQL data aggregation functions
AVG
COUNT
FIRST
GROUP BY
HAVING
LAST
MIN / MAX
STDEV / STDEVP
SUM
UNIQUECOUNT
AQL data retrieval functions
APPLICATIONNAME
ARIELSERVERS4EPID
ARIELSERVERS4EPNAME
ASSETHOSTNAME
ASSETPROPERTY
ASSETUSER
CATEGORYNAME
COMPONENTID
DOMAINNAME
GLOBALVIEW
GEO::LOOKUP
GEO::DISTANCE
HOSTNAME
INCIDR
INOFFENSE
LOGSOURCENAME
LOGSOURCEGROUPNAME
LOGSOURCETYPENAME
MATCHESASSETSEARCH
NETWORKNAME
OFFENSE_TIME
PARAMETERS EXCLUDESERVERS
PARAMETERS REMOTESERVERS
PROCESSORNAME
PROTOCOLNAME
QIDNAME
QIDESCRIPTION
REFERENCEMAP
REFERENCEMAPSETCONTAINS
REFERENCETABLE
REFERENCESETCONTAINS
RULENAME

AQL query design and usage
   Time criteria in AQL queries
   AQL date and time formats
   AQL subquery
   Grouping related events into sessions
   Transactional query refinements
   Conditional logic in AQL queries
   Bitwise operators in AQL queries
   CIDR IP addresses in AQL queries
   Custom properties in AQL queries

Examples
   System performance query examples
   Events and flows query examples
   Reference data query examples
   User and network monitoring query examples
   Event, flow, and simarc fields for AQL queries
    """,
    "Google Chronicle": """
1. Overview of YARA-L 2.0
2. Rule Structure
3. Meta Section Syntax
4. Events Section Syntax
   - Variable Declarations
   - Event Variable Filters
   - Event Variable Joins
5. Match Section Syntax
   - Time Duration & Correlation
   - Zero Value Handling
   - Hop Window
   - Sliding Window
6. Outcome Section Syntax
   - Outcome Variable Data Types
   - Conditional Logic
   - Mathematical Operations
   - Placeholder Variables in Outcomes
   - Aggregations
   - Outcome Variables in Assignment Expressions
7. Condition Section Syntax
   - Event and Placeholder Conditionals
   - Bounded and Unbounded Conditions
   - Non-Existence Rules
   - Outcome Conditionals
8. Options Section Syntax
   - allow_zero_values
   - suppression_window
9. Composite Detection Rules
   - Understand the Rule Structure
   - Define Inputs in Events Block
   - Reference Detection Content (outcomes, meta, IDs)
   - Join Inputs in Match Section
   - Define the Condition Section
   - Advanced Techniques (combine events/detections, sequential detections)
10. Risk Scores
11. Boolean Expressions
   - Comparisons
   - Functions (regex, ip_in_range)
   - Reference List Expressions
   - Logical Expressions (and/or/not)
12. Reference List Syntax
13. Enumerated Types
14. Nocase Modifier
15. Repeated Fields
   - any / all Modifiers
   - Unmodified Expressions
   - Placeholders with Repeated Fields
   - Outcomes with Repeated Fields
    """,
    "RSA NetWitness": """
NWDB Rule Syntax
Select Clause
Non-Aggregate Rule
Aggregate Rule
Aggregate Values
Collection Aggregation
Meta Aggregation
Supported Meta Aggregate Functions
Aggregate Query for Multiple Meta
Summarize
Order By
Session Threshold
Supported where Clause
Supported where Clause Operators
Supported then Clause
Limit Field
Rule Actions
dedup
filter_on
filter_out
lookup_and_add
max_threshold
min_threshold
regex
sum_count
sum_values
show_whats_new
Supported Rule Operators
IPDB Rule Syntax
Sample Supported Queries
Respond Rule Syntax
Select Clause
Non-Aggregate Rule
Aggregate Rule
Supported Aggregate Functions
Examples of Select Clause Syntax
Summarize
Alias
Where Clause
Supported where Clause Operators
Group By
Order By
Limit Field
Related Articles
Rule Syntax Dialog
Understanding and Creating RSA NetWitness Endpoint Alerts in v11.3
Fix Rules with Invalid Syntax
ESA Rule Syntax Error with meta index
How to use the not begins operator in NetWitness Reporting Engine query
    """,
    "default": """
    Focus on:
    - Rule syntax and structure optimization
    - Performance and efficiency improvements
    - Best practices for the specific SIEM platform
    - Error handling and edge case coverage
    - Documentation and maintainability
    - Security detection accuracy
    - False positive reduction
    - Alert tuning and threshold optimization
    - Integration and automation improvements
    - Compliance and audit requirements
    """,
}

# SIEM-specific keyword guidance
SIEM_KEYWORD_GUIDANCE = {
    "Splunk": """
    Guidance for RAG search keywords:
1. SPL basics: syntax, usage, manual, search language, SQL comparison
2. Quick reference: command quick reference, commands by category, command types
3. Evaluation functions: eval functions, bitwise, comparison, conditional, conversion, cryptographic, date time, informational, JSON, math, multivalue, statistical, text, trig, hyperbolic
4. Statistical & charting: aggregate functions, event order, multivalue stats, charting functions, time functions
5. Time handling: date time format variables, time modifiers
6. Search commands: abstract, accum, addcoltotals, addinfo, addtotals, analyzefields, anomalies, anomalousvalue, anomalydetection, append, appendcols, appendpipe, arules, associate, autoregress, bin, bucket, chart, cluster, collect, convert, correlate, datamodel, dbinspect, dedup, delete, delta, diff, eval, eventstats, extract, fields, filldown, fillnull, foreach, format, from, gauge, gentimes, geom, geostats, head, highlight, history, inputcsv, inputlookup, iplocation, join, kmeans, kvform, loadjob, lookup, makemv, makeresults, map, metadata, multisearch, mvcombine, mvexpand, outlier, outputcsv, outputlookup, pivot, predict, rare, regex, rename, replace, rest, return, rex, run, savedsearch, script, search, selfjoin, sendalert, sendemail, set, stats, strcat, streamstats, table, tags, tail, timechart, top, transaction, transpose, trendline, tstats, typeahead, union, uniq, where, xmlkv, xpath, xyseries
7. Internal commands: collapse, dump, findkeywords, makejson, mcatalog, noop, prjob, redistribute, runshellscript
8. CLI usage: search in CLI, syntax in CLI
    """,
    "Microsoft Sentinel": """
Guidance for RAG search on KQL:

1. Syntax conventions, comments, debug KQL with inline Python
2. Best practices for writing and optimizing KQL queries
3. Entity types, entity names, entity references
4. Databases, tables, columns, views, external tables, fact and dimension tables
5. Stored functions, user-defined functions
6. Scalar data types: bool, datetime, decimal, dynamic, guid, int, long, real, string, timespan, null values
7. Statistical functions: bartlett_test, binomial_test, ks_test, mann-whitney-u-test, t-test, wilcoxon_test
8. Machine learning and anomaly detection: dbscan, kmeans, predict, predict_onnx, series_* anomaly detection
9. Graph functions: graph_blast_radius, graph_exposure_perimeter, graph_node_centrality, graph_path_discovery
10. Visualization functions: plotly_anomaly, plotly_gauge, plotly_graph, plotly_scatter3d
11. Query statements: alias, let, pattern, query parameters, restrict, set, batches
12. Tabular expression statements and operators
13. Core operators: as, count, distinct, extend, project, where, sort, take, top
14. Join operators: cross-cluster join, broadcast join, time window join
15. Data parsing operators: parse, parse-where, parse-kv
16. Data expansion: mv-apply, mv-expand
17. Other operators: union, datatable, invoke, lookup, search, serialize, scan
18. Cross-cluster and cross-database queries: cluster(), database(), external_table()
19. Materialization and query cache: materialize(), materialized_view(), stored_query_result()
20. Operators and arithmetic: bitwise operators, datetime/timespan arithmetic, logical operators, numerical operators
21. Scalar functions: math (abs, exp, log, pow, sqrt), arrays (array_concat, array_slice, array_sum), strings (substring, replace_string, tolower, toupper), datetime (ago, datetime_add, endofmonth), conversion (todatetime, tostring, toint), hashing (hash_md5, hash_sha256), parsing (parse_json, parse_url, parse_user_agent)
22. Aggregation functions: count, sum, avg, min, max, dcount, hll, percentiles, tdigest, variance, stdev, covariance, make_list, make_set, make_bag
23. Geospatial functions: clustering, joins, visualizations, geo_distance, geo_intersects, geo_union, geo_point_to_h3cell, geo_polygon_to_s2cells
24. Window functions: next, prev, row_number, row_rank_dense, row_rank_min, row_cumsum, row_window_session
    """,
    "IBM QRadar": """
IBM QRadar AQL (Ariel Query Language) Guide
AQL query structure:
    SELECT statement
    WHERE clause
    GROUP BY clause
    HAVING clause
    ORDER BY clause
    LIKE clause
    COUNT function
    Quotation marks usage
    Sample AQL queries

AQL logical and comparison operators:
    =, !=, <, >, <=, >=
    BETWEEN, IN, NOT, OR, AND
    LIKE, ILIKE, MATCHES, IMATCHES
    TEXT SEARCH
    NULL / IS NOT NULL
    COLLATE
    INTO cursor

AQL data calculation and formatting functions:
    BASE64, CONCAT, DATEFORMAT
    DOUBLE, LONG, NOW
    PARSEDATETIME, PARSETIMESTAMP
    REPLACEALL, REPLACEFIRST
    STR, STRLEN, STRPOS
    SUBSTRING, LOWER, UPPER
    UTF8

AQL data aggregation functions:
    AVG, COUNT, FIRST
    GROUP BY, HAVING, LAST
    MIN, MAX
    STDEV, STDEVP
    SUM, UNIQUECOUNT

AQL data retrieval functions:
    APPLICATIONNAME
    ARIELSERVERS4EPID / ARIELSERVERS4EPNAME
    ASSETHOSTNAME, ASSETPROPERTY, ASSETUSER
    CATEGORYNAME, COMPONENTID, DOMAINNAME
    GLOBALVIEW
    GEO::LOOKUP, GEO::DISTANCE
    HOSTNAME
    INCIDR, INOFFENSE
    LOGSOURCENAME, LOGSOURCEGROUPNAME, LOGSOURCETYPENAME
    MATCHESASSETSEARCH
    NETWORKNAME
    OFFENSE_TIME
    PARAMETERS EXCLUDESERVERS, PARAMETERS REMOTESERVERS
    PROCESSORNAME, PROTOCOLNAME
    QIDNAME, QIDESCRIPTION
    REFERENCEMAP, REFERENCEMAPSETCONTAINS
    REFERENCETABLE, REFERENCESETCONTAINS
    RULENAME

Advanced AQL usage:
    Time criteria in queries (START, STOP, LAST)
    AQL date and time formats
    Subqueries
    Grouping related events into sessions
    Transactional query refinements
    Conditional logic
    Bitwise operators
    CIDR IP addresses
    Custom properties

Examples:
    System performance queries
    Events and flows queries
    Reference data queries
    User and network monitoring queries
    Event, flow, and simarc fields
    """,
    "Google Chronicle": """
1. Overview of YARA-L 2.0
   - Keywords: overview, introduction, language basics, syntax, SIEM support
2. Rule Structure
   - Keywords: rule structure, meta, events, match, outcome, condition, options, order of sections
3. Meta Section Syntax
   - Keywords: meta, metadata, key-value pairs, author, version, severity
4. Events Section Syntax
   - Keywords: events, variable declaration, event filters, joins, transitive join, boolean filter
5. Match Section Syntax
   - Keywords: match, correlation, time window, hop window, sliding window, zero value handling
6. Outcome Section Syntax
   - Keywords: outcome, outcome variables, risk_score, conditional logic, mathematical operations, aggregations, placeholder usage
7. Condition Section Syntax
   - Keywords: condition, event conditionals, placeholder conditionals, outcome conditionals, bounded, unbounded, non-existence rule
8. Options Section Syntax
   - Keywords: options, allow_zero_values, suppression_window, suppression_key, detection suppression
9. Composite Detection Rules
   - Keywords: composite rules, multi-event rules, collections, detection references, rule ID, rule name, sequential composite detection
10. Risk Scores
   - Keywords: risk_score, severity mapping, score ranges, critical, high, medium, low, observations
11. Boolean Expressions
   - Keywords: boolean, comparison, operators, regex, ip_in_range_cidr, logical and/or/not
12. Reference List Syntax
   - Keywords: reference list, lookup table, external list, expression with list
13. Enumerated Types
   - Keywords: enumerated types, UDM enums, predefined constants, performance optimization
14. Nocase Modifier
   - Keywords: nocase, case-insensitive comparison, regex case ignore
15. Repeated Fields
   - Keywords: repeated fields, any modifier, all modifier, unmodified expression, repeated placeholders, outcomes with repeated fields
    """,
    "RSA NetWitness": """
    Recommended search keywords:
NWDB Rule Syntax: select clause, non-aggregate rule, aggregate rule, collection aggregation, meta aggregation, aggregate functions (sum, count, countdistinct, min, max, avg, first, last, len, distinct), aggregate query multiple meta, summarize field, order by, session threshold, where clause syntax, where clause operators (=, !=, begins, contains, ends, exists, regex, not), then clause, limit field, rule actions (dedup, filter_on, filter_out, lookup_and_add, max_threshold, min_threshold, regex, sum_count, sum_values, show_whats_new), supported rule operators (*, =, !=, &&, ||, -u, l-, range)
IPDB Rule Syntax: IPDB rule syntax, IPDB supported queries
Respond Rule Syntax: select clause, non-aggregate rule, aggregate rule, aggregate functions (count, max, min, sum, avg), select clause examples, summarize field, alias, where clause, where clause operators (=, !=, >, >=, <, <=), group by, order by, limit field
Related Articles: rule syntax dialog, invalid syntax fix, ESA rule syntax error index lowercase, not begins operator usage, RSA NetWitness endpoint alerts v11.3
    """,
    "default": """
    Recommended search keywords:
    - siem_rule_optimization
    - security_detection_accuracy
    - false_positive_reduction
    - alert_tuning
    - performance_optimization
    - error_handling
    - documentation_improvement
    - integration_automation
    - compliance_requirements
    - best_practices
    """,
}


def get_system_prompt() -> str:
    """Get the system prompt for the OpenAI API."""
    return """You are a professional cybersecurity rule optimization expert. Your task is to analyze security rules and generate detailed optimization task lists.

Your output must be a valid JSON format with the following structure:
{
    "rule_type": "rule type",
    "total_tasks": total number of tasks,
    "tasks": [
        {
            "task_name": "task name",
            "description": "detailed task description",
            "search_keyword": "keyword"
        }
    ]
}

Please ensure:
1. Each task is a minimal unit that can be independently queried in documentation
2. Search keywords are specific enough to accurately locate relevant documentation
3. Task descriptions are clear and specific for subsequent RAG queries
4. Output format strictly follows JSON specification
5. All content is in English"""


def build_optimization_prompt(init_rule: str, rule_type: str) -> str:
    """Build the optimization prompt for the OpenAI API."""

    # Get type-specific guidance
    content_guidance, keyword_guidance = get_type_specific_guidance(rule_type)

    prompt = f"""Please analyze the following {rule_type} security rule and generate a detailed optimization task list.

Rule Type: {rule_type}

Rule Content:
{init_rule}

{content_guidance}

{keyword_guidance}

Please carefully analyze this rule, identify all aspects that can be optimized, and create a specific task for each optimization point. Each task should:

1. Have a clear optimization objective
2. Include specific search keywords to help find relevant information in official documentation
3. Provide a clear description of what needs to be optimized

Please ensure the generated task list helps users:
- Accurately locate relevant sections in official documentation
- Understand the specific content of each optimization point
- Plan optimization work effectively

Please ONLY output the result in JSON format, no other text or explanations.

Example:
{{
  "total_tasks": <number_of_tasks>,
  "tasks": [
    {{
      "task_name": "<placeholder_task_name>",
      "description": "<placeholder_task_description>",
      "search_keyword": "<placeholder_search_keyword>"
    }},
    {{
      "task_name": "<placeholder_task_name_2>",
      "description": "<placeholder_task_description_2>",
      "search_keyword": "<placeholder_search_keyword_2>"
    }},
    ...
  ]
}}

"""

    return prompt


def get_type_specific_guidance(rule_type: str) -> tuple[str, str]:
    """
    Get type-specific optimization guidance for different SIEMs.

    Args:
        rule_type: The SIEM type (e.g., "Splunk", "Microsoft Sentinel", etc.)

    Returns:
        tuple: (content_guidance, keyword_guidance) - Two strings containing guidance
    """
    content_guidance = SIEM_CONTENT_GUIDANCE.get(
        rule_type, SIEM_CONTENT_GUIDANCE["default"]
    )
    keyword_guidance = SIEM_KEYWORD_GUIDANCE.get(
        rule_type, SIEM_KEYWORD_GUIDANCE["default"]
    )

    return content_guidance, keyword_guidance


def get_agentic_rag_system_prompt() -> str:
    """Get the system prompt for Agentic RAG operations."""
    return """You are an expert security rule optimization agent specializing in SIEM platforms.

Your role is to:
1. Analyze optimization tasks and generate effective search strategies
2. Reflect on search results and adjust search approaches
3. Optimize security rules while preserving their semantic meaning
4. Provide clear explanations of optimizations made

Key principles:
- Always preserve the original rule's detection logic and threat coverage
- Use retrieved context to apply platform-specific best practices
- Maintain rule performance and efficiency
- Ensure semantic equivalence between original and optimized rules

Respond in a clear, technical manner with specific actionable insights."""


def build_rag_search_prompt(
    task: str, current_keywords: List[str], current_results: List[str]
) -> str:
    """Build a prompt for RAG search reflection and keyword adjustment."""
    return f"""Task: {task}

Current search keywords: {', '.join(current_keywords)}
Current search results: {current_results[:3]}

Based on the current search results, analyze if the keywords are effective:
1. Are the results relevant to the task?
2. What additional keywords might improve the search?
3. Should any current keywords be removed or modified?

Return only a JSON array of optimized keywords, no other text.
Example: ["keyword1", "keyword2", "keyword3"]"""


def build_rule_optimization_prompt(
    task: str, original_rule: str, context: List[str], rule_type: str
) -> str:
    """Build a prompt for rule optimization based on retrieved context."""
    return f"""You are optimizing a {rule_type} security rule based on retrieved documentation and best practices.

Task: {task}

Original Rule:
{original_rule}

Retrieved Context (Best Practices and Documentation):
{chr(10).join(f"- {ctx[:300]}..." for ctx in context[:3])}

CRITICAL SEMANTIC PRESERVATION REQUIREMENTS:
🚫 ABSOLUTELY FORBIDDEN:
- Changing ANY detection logic or conditions
- Adding or removing ANY threat detection criteria  
- Modifying ANY field names, values, or patterns that affect what gets detected
- Altering ANY logical operators (AND, OR, NOT) that change detection scope
- Changing ANY thresholds, timeframes, or numeric values that affect detection

✅ ALLOWED OPTIMIZATIONS ONLY:
- Improving syntax structure and formatting
- Optimizing keyword usage based on RAG documentation
- Enhancing code readability and organization
- Improving performance through better query structure
- Adding comments for maintainability
- Using platform-specific best practices for syntax

Instructions:
1. 🔒 PRESERVE SEMANTIC MEANING: The optimized rule MUST detect exactly the same threats/events as the original
2. Use retrieved context ONLY for syntax and structural improvements
3. Apply platform-specific optimizations for {rule_type} syntax and keywords
4. Improve performance, readability, and maintainability WITHOUT changing detection logic
5. Keep IDENTICAL detection logic, coverage, and threat scope

⚠️  VERIFICATION: Before finalizing, double-check that your optimized rule will trigger on the EXACT same events as the original rule.

Return the optimized rule in the same format as the original, with no additional text or explanations.

Example:
```{rule_type}
<optimized rule content>
```
"""
