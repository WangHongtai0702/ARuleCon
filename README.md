# RulePilot

A security rule generation and conversion tool powered by Large Language Models (LLMs).

## Features

- **Rule Generation**: Generate security rules from natural language descriptions
- **Rule Conversion**: Convert rules between different SIEM platforms (Splunk, Microsoft Sentinel, IBM QRadar, Google Chronicle, RSA NetWitness)
- **Intermediate Representation**: Use structured IR format for accurate rule conversion
- **LLM Integration**: Powered by OpenAI's GPT models for intelligent rule processing

## Project Structure

```
RulePilot/
├── app.py                          # Main Streamlit application
├── src/                            # Source code
│   ├── core/                       # Core functionality
│   │   ├── rule_types.py          # Rule type definitions
│   │   ├── rule_generator.py      # Rule generation logic
│   │   └── rule_converter.py      # Rule conversion logic
│   ├── llms/                       # LLM integration
│   │   ├── client.py              # OpenAI client management
│   │   ├── prompts.py             # All LLM prompts
│   │   └── agents.py              # LLM agents
│   ├── utils/                      # Utility functions
│   │   ├── helpers.py             # General helper functions
│   │   └── validators.py          # Validation functions
│   ├── pages/                      # Streamlit pages
│   │   ├── rule_generation.py     # Rule generation page
│   │   ├── rule_conversion.py     # Rule conversion page
│   │   └── rule_ir_generation.py  # IR generation page
│   └── schemas/                    # Data models
│       └── models.py              # Data structures
├── tests/                          # Test suite
├── dataset/                        # Sample data and rules
└── requirements.txt                # Python dependencies
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/rulepilot/rulepilot.git
cd rulepilot
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your OpenAI API key
```

## Usage

### Running the Application

```bash
streamlit run app.py
```

### Using the API

```python
from src.core import RuleGenerator, RuleConverter

# Generate a rule
generator = RuleGenerator()
rule = generator.web_rule_generator(
    description="Detect failed login attempts",
    rule_type="Splunk",
    model="gpt-4"
)

# Convert a rule
converter = RuleConverter()
converted = converter.convert_rule(
    rule_content=rule,
    target_type="Microsoft Sentinel",
    source_type="Splunk",
    model="gpt-4"
)
```

## Supported Rule Types

- **Splunk SPL**: Search Processing Language
- **Microsoft Sentinel KQL**: Kusto Query Language
- **IBM QRadar AQL**: Advanced Query Language
- **Google Chronicle YARA-L**: YARA Language for Chronicle
- **RSA NetWitness ESA**: Event Stream Analysis

## Development

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black src/ tests/
```

### Type Checking

```bash
mypy src/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions, please open an issue on GitHub.
