# ARuleCon - AI-Powered SIEM Rule Converter

ARuleCon is an intelligent security rule conversion platform that enables seamless transformation of detection rules between different SIEM (Security Information and Event Management) platforms using AI-powered Intermediate Representation (IR) technology.

## 🚀 Features

- **Multi-SIEM Support**: Convert rules between Splunk, Microsoft Sentinel, Google Chronicle, IBM QRadar, and RSA NetWitness
- **AI-Powered Conversion**: Uses Large Language Models (LLM) for intelligent rule analysis and conversion
- **Intermediate Representation**: Employs IR as a universal format for accurate cross-platform rule translation
- **Rule Generation**: Generate new detection rules from natural language descriptions
- **Rule Optimization**: Syntax and semantic optimization for improved rule performance
- **Batch Processing**: Convert multiple rules simultaneously with progress tracking
- **Vector Database**: RAG (Retrieval-Augmented Generation) support for enhanced rule understanding
- **Web Interface**: User-friendly Streamlit-based web application

## 🛠️ Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd ARuleCon
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   # Create .env file
   echo "OPENAI_API_KEY=your_openai_api_key_here" > .env
   echo "MODEL_NAME=gpt-4o-mini" >> .env
   ```

## 🚀 Quick Start

### Web Interface

1. **Start the Streamlit application**

   ```bash
   streamlit run app.py
   ```

2. **Open your browser** and navigate to `http://localhost:8501`

3. **Configure your OpenAI API key** in the sidebar

4. **Select a function**:
   - **Rule Conversion**: Convert rules between different SIEM platforms
   - **Rule Generation**: Generate new rules from descriptions
   - **Rule IR Generation**: Generate Intermediate Representation from rules
   - **Semantic Optimization Test**: Test and optimize rule semantics

### Command Line Interface

1. **Batch rule conversion**

   ```bash
   # Convert 10 Splunk rules to Microsoft Sentinel
   python script/batch_rule_conversion.py --source Splunk --target "Microsoft Sentinel" --num-rules 10
   ```

2. **List available SIEM types**

   ```bash
   python script/batch_rule_conversion.py --list-siems
   ```

3. **Count rules for a specific SIEM**
   ```bash
   python script/batch_rule_conversion.py --count Splunk
   ```

## 📁 Project Structure

```
ARuleCon/
├── app.py                          # Main Streamlit application
├── settings.py                     # Configuration settings
├── requirements.txt                # Python dependencies
├── src/                           # Source code
│   ├── core/                      # Core conversion logic
│   │   ├── rule_converter.py      # Rule conversion engine
│   │   ├── rule_generator.py      # Rule generation
│   │   ├── rule_optimizer.py      # Rule optimization
│   │   └── agentic_rag.py         # RAG implementation
│   ├── llms/                      # LLM integration
│   │   ├── client.py              # LLM client
│   │   └── prompts.py             # AI prompts
│   ├── pages/                     # Web interface pages
│   ├── schemas/                   # Data models
│   └── utils/                     # Utilities
├── script/                        # Command-line tools
├── dataset/                       # Sample rules and documentation
│   ├── rules/                     # Rule samples by SIEM
│   └── documentations/            # SIEM documentation
└── vector_db/                     # Vector database for RAG
```

## 🔧 Configuration

The application can be configured through `settings.py`:

- **SIEM Rule Paths**: Configure paths to rule samples
- **Documentation Paths**: Set paths to SIEM documentation
- **Vector Database Paths**: Configure vector database locations
- **Supported File Extensions**: Define supported file types per SIEM

## 📞 Support

For support, questions, or feature requests, please open an issue on GitHub.

---

**ARuleCon** - Making SIEM rule conversion intelligent and effortless.
