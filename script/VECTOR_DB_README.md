# Vector Database Build Script

## Overview

This script processes PDF documents in the `dataset/documentations` directory, performs intelligent chunking and vectorization, and builds a vector database for RAG applications.

## Features

### 🔍 **Intelligent Document Chunking**

- **Header-based Chunking**: Automatically identifies markdown-style header structures
- **TOC-based Chunking**: Detects document table of contents structure
- **Numbered Section Chunking**: Identifies numerically numbered sections
- **Semantic Unit Chunking**: Intelligent chunking by paragraphs and sentences

### 📚 **Multi-SIEM Support**

- Splunk
- Microsoft Sentinel
- IBM QRadar
- Google Chronicle
- RSA NetWitness

### 🗄️ **Vector Database**

- Uses ChromaDB as vector storage
- **Multi-collection Architecture**: Each SIEM has its own independent collection
- Supports persistent storage
- Integrates sentence-transformers for vectorization

### 📁 **Folder Structure Organization**

```
vector_db/
├── Splunk/                    # Splunk related documents and collections
├── Microsoft Sentinel/        # Microsoft Sentinel related documents and collections
├── IBM QRadar/               # IBM QRadar related documents and collections
├── Google Chronicle/          # Google Chronicle related documents and collections
├── RSA NetWitness/           # RSA NetWitness related documents and collections
└── chroma.sqlite3            # ChromaDB database file
```

## Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. The Script Will Automatically:

- Scan the `dataset/documentations` directory
- Process all PDF files
- Perform intelligent chunking
- Build the vector database
- Create independent collections and folders for each SIEM

## Usage

### 1. **Build Vector Database**

```bash
cd script
python build_vector_db.py
```

### 2. **Query Vector Database**

```bash
cd script
python query_vector_db.py
```

### 3. **Test Database Structure**

```bash
cd script
python test_vector_db_structure.py
```

## Chunking Strategies

### 1. **Header-based Chunking**

Suitable for documents with clear header structures:

```markdown
# Main Title

Content...

## Subtitle

More content...

### Third-level Title

Detailed content...
```

### 2. **TOC-based Chunking**

Detects table of contents structure in documents and chunks by sections.

### 3. **Numbered Section Chunking**

Identifies numerically numbered section structures:

```
1. Chapter One

Content...

2. Chapter Two

More content...
```

### 4. **Semantic Unit Chunking**

When document structure is unclear, performs intelligent chunking by paragraphs and sentences.

## Configuration Parameters

### Chunking Parameters

```python
processor = PDFDocumentProcessor(
    chunk_size=1000,      # Maximum characters per chunk
    chunk_overlap=200     # Overlapping characters between chunks
)
```

### Vector Database Parameters

```python
vector_db = VectorDatabaseBuilder(
    db_path="./vector_db"  # Database storage path
)
```

## Output Structure

### 1. **Vector Database**

- Location: `./vector_db/`
- Format: ChromaDB persistent storage
- Collection Structure: One independent collection per SIEM
  - `siem_splunk`
  - `siem_microsoft_sentinel`
  - `siem_ibm_qradar`
  - `siem_google_chronicle`
  - `siem_rsa_netwitness`

### 2. **Processing Report**

- File: `processing_summary.json`
- Content: Processing statistics, SIEM classification, database information, output structure

### 3. **Log Files**

- File: `vector_db_build.log`
- Content: Detailed processing logs

## Query Functions

### 1. **SIEM-Specific Query**

```python
# Query documents for a specific SIEM
results = vector_db.search("security rule", siem_name="Splunk", n_results=5)
```

### 2. **Cross-SIEM Query**

```python
# Search across all SIEMs
results = vector_db.search("security rule", n_results=10)
```

### 3. **Collection Information Query**

```python
# Get information for all collections
info = vector_db.get_collection_info()
```

## Processing Summary

```
==================================================
PROCESSING SUMMARY
==================================================
Total files processed: 15
Total chunks created: 1250
Vector database path: ./vector_db

SIEM Breakdown:
  Splunk: 3 files, 250 chunks
  Microsoft Sentinel: 4 files, 300 chunks
  IBM QRadar: 3 files, 200 chunks
  Google Chronicle: 3 files, 250 chunks
  RSA NetWitness: 2 files, 150 chunks

Output Directory Structure:
  ./vector_db/Splunk
  ./vector_db/Microsoft Sentinel
  ./vector_db/IBM QRadar
  ./vector_db/Google Chronicle
  ./vector_db/RSA NetWitness

Vector database ready for RAG applications!
Each SIEM has its own collection and directory structure.
```

### Vector Database Information

```json
{
  "total_collections": 5,
  "collections": {
    "Splunk": {
      "name": "siem_splunk",
      "total_chunks": 250,
      "metadata": {
        "description": "Documentation chunks for Splunk",
        "siem": "Splunk"
      }
    }
  },
  "database_path": "./vector_db"
}
```

## Advanced Usage

### 1. **Batch Process Specific SIEM**

```python
from build_vector_db import PDFDocumentProcessor, VectorDatabaseBuilder

# Process only Splunk documents
processor = PDFDocumentProcessor()
vector_db = VectorDatabaseBuilder("./vector_db")

# Process specific SIEM
siem_name = "Splunk"
# ... processing logic
```

### 2. **Custom Chunking Strategy**

```python
# Create custom chunker
processor = PDFDocumentProcessor(
    chunk_size=500,      # Smaller chunks
    chunk_overlap=100    # Less overlap
)
```

## Common Issues

1. **PDF Text Extraction Failure**

   ```
   Error: Error extracting text from PDF
   Solution: The script will automatically use PyPDF2 as a fallback
   ```

2. **Dependency Installation Failure**

   ```
   Error: ModuleNotFoundError
   Solution: Ensure all dependency packages are installed
   ```

3. **Insufficient Memory**

   ```
   Error: MemoryError
   Solution: Reduce chunk_size or process large documents in batches
   ```

## Troubleshooting

### Enable Verbose Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### 1. **Chunking Strategy Optimization**

- For technical documents, use smaller chunk_size (500-1000)
- For long documents, increase chunk_overlap (200-300)

### 2. **Memory Management**

- Process large documents in batches
- Clean up temporary variables promptly

### 3. **Parallel Processing**

- Can modify the script to support multi-process processing
- Note the concurrency limitations of the vector database

## Extended Features

### 1. **Support More Document Formats**

- Word documents (.docx)
- Plain text files (.txt)
- Markdown files (.md)

### 2. **Enhanced Chunking Strategies**

- Table-based chunking
- Image-based chunking
- Code block-based chunking

### 3. **Multi-language Support**

- Chinese document processing
- Multi-language mixed documents

## Contributing

Welcome to submit Issues and Pull Requests to improve this script!

## License

This project is licensed under the MIT License.
