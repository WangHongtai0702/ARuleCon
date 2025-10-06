#!/usr/bin/env python3
"""
PDF Document Vector Database Builder for SIEM Documentation

This script processes PDF files from dataset/documentations directory,
performs intelligent chunking based on document structure,
and builds a vector database for RAG applications.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import hashlib
import re

# PDF processing
import PyPDF2
from PyPDF2 import PdfReader
import fitz  # PyMuPDF for better text extraction

# Text processing and chunking
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.text_splitter import MarkdownHeaderTextSplitter
import nltk
from nltk.tokenize import sent_tokenize

# Vector database
import chromadb
from chromadb.config import Settings
import numpy as np

# Embeddings
from sentence_transformers import SentenceTransformer

# Progress tracking
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("vector_db_build.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Download required NLTK data
try:
    nltk.data.find("tokenizers/punkt")
except LookupError:
    nltk.download("punkt")


class PDFDocumentProcessor:
    """Processes PDF documents with intelligent chunking strategies."""

    def __init__(self, chunk_size: int = 1000, chunk_overlap: int = 200):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

        # Initialize text splitter
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            length_function=len,
            separators=["\n\n", "\n", ". ", " ", ""],
        )

        # Initialize markdown header splitter for structured documents
        self.header_splitter = MarkdownHeaderTextSplitter(
            headers_to_split_on=[
                ("#", "Header 1"),
                ("##", "Header 2"),
                ("###", "Header 3"),
                ("####", "Header 4"),
            ]
        )

    def extract_text_from_pdf(self, pdf_path: str) -> str:
        """Extract text from PDF using PyMuPDF for better quality."""
        try:
            doc = fitz.open(pdf_path)
            text = ""

            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                text += page.get_text()
                text += "\n\n"  # Add page separator

            doc.close()
            return text

        except Exception as e:
            logger.error(f"Error extracting text from {pdf_path}: {str(e)}")
            # Fallback to PyPDF2
            try:
                with open(pdf_path, "rb") as file:
                    reader = PdfReader(file)
                    text = ""
                    for page in reader.pages:
                        text += page.extract_text() + "\n\n"
                    return text
            except Exception as e2:
                logger.error(f"PyPDF2 fallback also failed for {pdf_path}: {str(e2)}")
                return ""

    def detect_document_structure(self, text: str) -> Dict[str, Any]:
        """Detect document structure and identify sections."""
        structure = {
            "has_headers": False,
            "has_toc": False,
            "sections": [],
            "estimated_type": "unstructured",
        }

        # Check for markdown-style headers
        header_pattern = r"^(#{1,6})\s+(.+)$"
        headers = re.findall(header_pattern, text, re.MULTILINE)

        if headers:
            structure["has_headers"] = True
            structure["sections"] = [
                {"level": len(h[0]), "title": h[1].strip()} for h in headers
            ]
            structure["estimated_type"] = "markdown_structured"

        # Check for table of contents patterns
        toc_patterns = [
            r"table\s+of\s+contents",
            r"contents",
            r"index",
            r"目录",
            r"目次",
        ]

        for pattern in toc_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                structure["has_toc"] = True
                break

        # Check for numbered sections
        numbered_section_pattern = r"^\d+\.\s+(.+)$"
        numbered_sections = re.findall(numbered_section_pattern, text, re.MULTILINE)

        if numbered_sections and not structure["has_headers"]:
            structure["sections"] = [
                {"level": 1, "title": s.strip()} for s in numbered_sections
            ]
            structure["estimated_type"] = "numbered_structured"

        return structure

    def intelligent_chunking(
        self, text: str, metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Perform intelligent chunking based on document structure."""
        structure = self.detect_document_structure(text)

        if structure["has_headers"]:
            return self._chunk_by_headers(text, metadata, structure)
        elif structure["has_toc"]:
            return self._chunk_by_toc(text, metadata, structure)
        elif structure["estimated_type"] == "numbered_structured":
            return self._chunk_by_numbered_sections(text, metadata, structure)
        else:
            return self._chunk_by_semantic_units(text, metadata)

    def _chunk_by_headers(
        self, text: str, metadata: Dict[str, Any], structure: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Chunk text based on markdown-style headers."""
        chunks = []

        # Split by headers
        lines = text.split("\n")
        current_chunk = ""
        current_header = "Introduction"
        chunk_id = 0

        for line in lines:
            # Check if line is a header
            header_match = re.match(r"^(#{1,6})\s+(.+)$", line)

            if header_match:
                # Save previous chunk
                if current_chunk.strip():
                    chunks.append(
                        {
                            "id": f"{metadata['siem']}_{metadata['filename']}_{chunk_id}",
                            "content": current_chunk.strip(),
                            "header": current_header,
                            "metadata": {
                                **metadata,
                                "chunk_type": "header_based",
                                "section_header": current_header,
                                "chunk_size": len(current_chunk.strip()),
                            },
                        }
                    )
                    chunk_id += 1

                # Start new chunk
                current_header = header_match.group(2).strip()
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"

        # Add final chunk
        if current_chunk.strip():
            chunks.append(
                {
                    "id": f"{metadata['siem']}_{metadata['filename']}_{chunk_id}",
                    "content": current_chunk.strip(),
                    "header": current_header,
                    "metadata": {
                        **metadata,
                        "chunk_type": "header_based",
                        "section_header": current_header,
                        "chunk_size": len(current_chunk.strip()),
                    },
                }
            )

        return chunks

    def _chunk_by_toc(
        self, text: str, metadata: Dict[str, Any], structure: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Chunk text based on table of contents."""
        # This is a simplified approach - in practice, you might want more sophisticated TOC parsing
        return self._chunk_by_semantic_units(text, metadata)

    def _chunk_by_numbered_sections(
        self, text: str, metadata: Dict[str, Any], structure: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Chunk text based on numbered sections."""
        chunks = []

        # Split by numbered sections
        sections = re.split(r"^\d+\.\s+", text, flags=re.MULTILINE)

        for i, section in enumerate(sections):
            if section.strip():
                # Find the section title (first line)
                lines = section.strip().split("\n")
                title = lines[0].strip() if lines else f"Section {i}"
                content = "\n".join(lines[1:]) if len(lines) > 1 else section.strip()

                if content.strip():
                    chunks.append(
                        {
                            "id": f"{metadata['siem']}_{metadata['filename']}_{i}",
                            "content": content.strip(),
                            "header": title,
                            "metadata": {
                                **metadata,
                                "chunk_type": "numbered_section",
                                "section_header": title,
                                "section_number": i,
                                "chunk_size": len(content.strip()),
                            },
                        }
                    )

        return chunks

    def _chunk_by_semantic_units(
        self, text: str, metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Chunk text using semantic units (paragraphs, sentences)."""
        chunks = []

        # Split by paragraphs first
        paragraphs = text.split("\n\n")

        for i, paragraph in enumerate(paragraphs):
            if paragraph.strip():
                # Further split long paragraphs
                if len(paragraph.strip()) > self.chunk_size * 2:
                    # Use sentence-based splitting for long paragraphs
                    sentences = sent_tokenize(paragraph.strip())
                    current_chunk = ""

                    chunk_counter = 0
                    for sentence in sentences:
                        if len(current_chunk + sentence) > self.chunk_size:
                            if current_chunk.strip():
                                chunks.append(
                                    {
                                        "id": f"{metadata['siem']}_{metadata['filename']}_{i}_s_{chunk_counter}",
                                        "content": current_chunk.strip(),
                                        "header": f"Paragraph {i}",
                                        "metadata": {
                                            **metadata,
                                            "chunk_type": "semantic_unit",
                                            "section_header": f"Paragraph {i}",
                                            "chunk_size": len(current_chunk.strip()),
                                        },
                                    }
                                )
                                chunk_counter += 1
                            current_chunk = sentence + " "
                        else:
                            current_chunk += sentence + " "

                    # Add remaining content
                    if current_chunk.strip():
                        chunks.append(
                            {
                                "id": f"{metadata['siem']}_{metadata['filename']}_{i}_s_{chunk_counter}",
                                "content": current_chunk.strip(),
                                "header": f"Paragraph {i}",
                                "metadata": {
                                    **metadata,
                                    "chunk_type": "semantic_unit",
                                    "section_header": f"Paragraph {i}",
                                    "chunk_size": len(current_chunk.strip()),
                                },
                            }
                        )
                else:
                    chunks.append(
                        {
                            "id": f"{metadata['siem']}_{metadata['filename']}_{i}",
                            "content": paragraph.strip(),
                            "header": f"Paragraph {i}",
                            "metadata": {
                                **metadata,
                                "chunk_type": "semantic_unit",
                                "section_header": f"Paragraph {i}",
                                "chunk_size": len(paragraph.strip()),
                            },
                        }
                    )

        return chunks


class VectorDatabaseBuilder:
    """Builds and manages separate vector databases for each SIEM."""

    def __init__(self, base_db_path: str = "./vector_db"):
        self.base_db_path = Path(base_db_path)
        self.siem_databases = {}  # Store database instances for each SIEM

        # Initialize embedding model
        self.embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

        # Create base database directory
        self.base_db_path.mkdir(parents=True, exist_ok=True)

        # Auto-discover existing SIEM databases
        self._discover_existing_databases()

    def _discover_existing_databases(self):
        """Discover and load existing SIEM databases."""
        if not self.base_db_path.exists():
            return

        # Look for SIEM directories
        siem_dirs = [
            "Splunk",
            "Microsoft Sentinel",
            "IBM QRadar",
            "Google Chronicle",
            "RSA NetWitness",
        ]

        for siem in siem_dirs:
            siem_db_path = self.base_db_path / siem
            if siem_db_path.exists():
                try:
                    # Try to load existing database
                    client = chromadb.PersistentClient(
                        path=str(siem_db_path),
                        settings=Settings(anonymized_telemetry=False, allow_reset=True),
                    )

                    # Try to get existing collection
                    collection_name = (
                        f"siem_{siem.lower().replace(' ', '_').replace('-', '_')}"
                    )
                    try:
                        collection = client.get_collection(name=collection_name)

                        # Store database info
                        self.siem_databases[siem] = {
                            "client": client,
                            "collection": collection,
                            "path": siem_db_path,
                            "collection_name": collection_name,
                        }

                        logger.info(
                            f"Loaded existing database for {siem} from {siem_db_path}"
                        )

                    except Exception as e:
                        logger.warning(
                            f"Collection {collection_name} not found for {siem}: {str(e)}"
                        )
                        # Collection doesn't exist, but we'll create it when needed

                except Exception as e:
                    logger.warning(
                        f"Failed to load existing database for {siem}: {str(e)}"
                    )

    def get_or_create_siem_database(self, siem_name: str):
        """Get or create a vector database for a specific SIEM."""
        if siem_name not in self.siem_databases:
            try:
                # Create SIEM-specific database directory
                siem_db_path = self.base_db_path / siem_name
                siem_db_path.mkdir(parents=True, exist_ok=True)

                # Initialize ChromaDB client for this SIEM
                client = chromadb.PersistentClient(
                    path=str(siem_db_path),
                    settings=Settings(anonymized_telemetry=False, allow_reset=True),
                )

                # Create collection for this SIEM
                collection_name = (
                    f"siem_{siem_name.lower().replace(' ', '_').replace('-', '_')}"
                )

                # Get relative paths for metadata
                script_dir = Path(__file__).parent
                project_root = script_dir.parent
                relative_db_path = Path("vector_db") / siem_name

                collection = client.get_or_create_collection(
                    name=collection_name,
                    metadata={
                        "description": f"Documentation chunks for {siem_name}",
                        "siem": siem_name,
                        "created_at": (
                            str(Path().cwd().relative_to(project_root))
                            if Path().cwd().is_relative_to(project_root)
                            else str(Path().cwd())
                        ),
                        "database_path": str(relative_db_path),
                    },
                )

                # Store database info
                self.siem_databases[siem_name] = {
                    "client": client,
                    "collection": collection,
                    "path": siem_db_path,
                    "collection_name": collection_name,
                }

                logger.info(
                    f"Created/retrieved database for {siem_name} at {siem_db_path}"
                )

            except Exception as e:
                logger.error(f"Failed to create database for {siem_name}: {str(e)}")
                raise

        return self.siem_databases[siem_name]

    def add_documents(self, chunks: List[Dict[str, Any]], siem_name: str):
        """Add document chunks to the vector database for a specific SIEM."""
        if not chunks:
            return

        try:
            # Get or create database for this SIEM
            db_info = self.get_or_create_siem_database(siem_name)
            collection = db_info["collection"]

            # Prepare data for ChromaDB
            ids = []
            documents = []
            metadatas = []

            for chunk in chunks:
                ids.append(chunk["id"])
                documents.append(chunk["content"])
                metadatas.append(chunk["metadata"])

            # Add to collection
            collection.add(ids=ids, documents=documents, metadatas=metadatas)

            logger.info(
                f"Added {len(chunks)} chunks to {siem_name} database at {db_info['path']}"
            )

        except Exception as e:
            logger.error(f"Failed to add documents to {siem_name} database: {str(e)}")
            raise

    def search(
        self, query: str, siem_name: str = None, n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """Search the vector database."""
        try:
            if siem_name:
                # Search in specific SIEM database
                if siem_name not in self.siem_databases:
                    logger.warning(f"Database for {siem_name} not found")
                    return []

                db_info = self.siem_databases[siem_name]
                collection = db_info["collection"]
                results = collection.query(query_texts=[query], n_results=n_results)
            else:
                # Search across all databases
                all_results = []
                for siem, db_info in self.siem_databases.items():
                    try:
                        collection = db_info["collection"]
                        results = collection.query(
                            query_texts=[query], n_results=n_results
                        )
                        # Add SIEM information to results
                        if results and results.get("documents"):
                            for i, doc in enumerate(results["documents"][0]):
                                if results.get("metadatas") and results["metadatas"][0]:
                                    results["metadatas"][0][i]["siem"] = siem
                        all_results.append(results)
                    except Exception as e:
                        logger.warning(f"Search failed for {siem}: {str(e)}")
                        continue

                # Combine results (simplified approach)
                if all_results:
                    results = all_results[0]  # Return first successful result for now
                else:
                    results = {}

            return results

        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            return []

    def get_database_info(self) -> Dict[str, Any]:
        """Get information about all databases."""
        try:
            info = {
                "total_databases": len(self.siem_databases),
                "databases": {},
                "base_path": "vector_db",  # Use relative path from project root
            }

            for siem_name, db_info in self.siem_databases.items():
                try:
                    collection = db_info["collection"]
                    count = collection.count()

                    # Convert absolute path to relative path from project root
                    absolute_path = Path(db_info["path"])
                    project_root = Path(__file__).parent.parent
                    relative_path = absolute_path.relative_to(project_root)

                    info["databases"][siem_name] = {
                        "collection_name": db_info["collection_name"],
                        "database_path": str(relative_path),  # Store relative path
                        "total_chunks": count,
                        "metadata": collection.metadata,
                    }
                except Exception as e:
                    logger.warning(
                        f"Failed to get info for {siem_name} database: {str(e)}"
                    )
                    info["databases"][siem_name] = {"error": str(e)}

            return info

        except Exception as e:
            logger.error(f"Failed to get database info: {str(e)}")
            return {"error": str(e)}


def process_siem_documentation():
    """Main function to process all SIEM documentation."""

    # Configuration - ensure vector_db is created in project root
    base_path = Path("dataset/documentations")

    # Get the script's directory and go up to project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    output_path = project_root / "vector_db"

    # Initialize components
    processor = PDFDocumentProcessor(chunk_size=1000, chunk_overlap=200)
    vector_db = VectorDatabaseBuilder(str(output_path))

    # SIEM directories
    siem_dirs = [
        "Splunk",
        "Microsoft Sentinel",
        "IBM QRadar",
        "Google Chronicle",
        "RSA NetWitness",
    ]

    total_chunks = 0
    processed_files = []

    for siem in siem_dirs:
        siem_path = base_path / siem
        if not siem_path.exists():
            logger.warning(f"Directory {siem_path} does not exist, skipping...")
            continue

        logger.info(f"Processing {siem} documentation...")

        # Find PDF files
        pdf_files = list(siem_path.glob("*.pdf"))

        if not pdf_files:
            logger.info(f"No PDF files found in {siem_path}")
            continue

        for pdf_file in tqdm(pdf_files, desc=f"Processing {siem}"):
            try:
                logger.info(f"Processing {pdf_file.name}...")

                # Extract text
                text = processor.extract_text_from_pdf(str(pdf_file))

                if not text.strip():
                    logger.warning(f"No text extracted from {pdf_file.name}")
                    continue

                # Prepare metadata
                metadata = {
                    "siem": siem,
                    "filename": pdf_file.stem,
                    "file_path": str(pdf_file),
                    "file_size": pdf_file.stat().st_size,
                    "processing_timestamp": str(Path().cwd()),
                }

                # Perform intelligent chunking
                chunks = processor.intelligent_chunking(text, metadata)

                if chunks:
                    # Add to vector database
                    vector_db.add_documents(chunks, siem)

                    total_chunks += len(chunks)
                    processed_files.append(
                        {
                            "siem": siem,
                            "filename": pdf_file.name,
                            "chunks": len(chunks),
                            "file_size": pdf_file.stat().st_size,
                        }
                    )

                    logger.info(
                        f"Successfully processed {pdf_file.name} into {len(chunks)} chunks"
                    )
                else:
                    logger.warning(f"No chunks generated for {pdf_file.name}")

            except Exception as e:
                logger.error(f"Error processing {pdf_file.name}: {str(e)}")
                continue

    # Generate summary report
    summary = {
        "total_files_processed": len(processed_files),
        "total_chunks_created": total_chunks,
        "siem_breakdown": {},
        "vector_database_info": vector_db.get_database_info(),
    }

    # Calculate SIEM breakdown
    for file_info in processed_files:
        siem = file_info["siem"]
        if siem not in summary["siem_breakdown"]:
            summary["siem_breakdown"][siem] = {"files": 0, "chunks": 0, "total_size": 0}

        summary["siem_breakdown"][siem]["files"] += 1
        summary["siem_breakdown"][siem]["chunks"] += file_info["chunks"]
        summary["siem_breakdown"][siem]["total_size"] += file_info["file_size"]

    # Save summary in project root
    summary_path = project_root / "processing_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # Print summary
    logger.info("=" * 50)
    logger.info("PROCESSING SUMMARY")
    logger.info("=" * 50)
    logger.info(f"Total files processed: {summary['total_files_processed']}")
    logger.info(f"Total chunks created: {summary['total_chunks_created']}")
    logger.info(
        f"Vector database base path: {summary['vector_database_info'].get('base_path', 'N/A')}"
    )

    logger.info("\nSIEM Breakdown:")
    for siem, stats in summary["siem_breakdown"].items():
        logger.info(f"  {siem}: {stats['files']} files, {stats['chunks']} chunks")

    logger.info("\nDatabase Structure:")
    for siem, db_info in summary["vector_database_info"].get("databases", {}).items():
        if "error" not in db_info:
            logger.info(
                f"  {siem}: {db_info['database_path']} ({db_info['total_chunks']} chunks)"
            )

    logger.info("\nVector database ready for RAG applications!")
    logger.info("Each SIEM has its own independent vector database.")
    logger.info(f"Database location: vector_db/")  # Use relative path in log

    return summary


def test_vector_database():
    """Test the vector database with sample queries."""
    try:
        # Get the script's directory and go up to project root
        script_dir = Path(__file__).parent
        project_root = script_dir.parent
        vector_db_path = project_root / "vector_db"

        # Use path relative to project root
        vector_db = VectorDatabaseBuilder(str(vector_db_path))

        # Get database info first
        info = vector_db.get_database_info()
        logger.info("Vector Database Structure:")
        for siem, db_info in info.get("databases", {}).items():
            logger.info(
                f"  {siem}: {db_info.get('collection_name', 'Unknown')} at {db_info.get('database_path', 'Unknown')} - {db_info.get('total_chunks', 0)} chunks"
            )

        # Test queries for different SIEMs
        test_queries = [
            ("Splunk", "How to optimize Splunk search queries?"),
            ("Microsoft Sentinel", "Microsoft Sentinel KQL performance tips"),
            ("IBM QRadar", "IBM QRadar rule configuration"),
            ("Google Chronicle", "Google Chronicle YARA-L syntax"),
            ("RSA NetWitness", "RSA NetWitness correlation rules"),
        ]

        logger.info("\nTesting vector database with sample queries...")

        for siem, query in test_queries:
            logger.info(f"\nQuery for {siem}: {query}")

            # Test SIEM-specific search
            results = vector_db.search(query, siem_name=siem, n_results=3)

            if results and results.get("documents"):
                for i, doc in enumerate(results["documents"][0]):
                    metadata = (
                        results["metadatas"][0][i] if results.get("metadatas") else {}
                    )
                    logger.info(f"  Result {i+1}: {doc[:100]}...")
                    logger.info(
                        f"    Source: {metadata.get('siem', 'Unknown')} - {metadata.get('filename', 'Unknown')}"
                    )
            else:
                logger.info("  No results found")

        # Test cross-database search
        logger.info("\nTesting cross-database search...")
        cross_query = "security rule optimization"
        results = vector_db.search(cross_query, n_results=5)

        if results and results.get("documents"):
            logger.info(f"Cross-database results for: {cross_query}")
            for i, doc in enumerate(results["documents"][0]):
                metadata = (
                    results["metadatas"][0][i] if results.get("metadatas") else {}
                )
                logger.info(f"  Result {i+1}: {doc[:100]}...")
                logger.info(
                    f"    Source: {metadata.get('siem', 'Unknown')} - {metadata.get('filename', 'Unknown')}"
                )

    except Exception as e:
        logger.error(f"Vector database test failed: {str(e)}")


if __name__ == "__main__":
    try:
        # Process documentation
        summary = process_siem_documentation()

        # Test the database
        test_vector_database()

        logger.info("Vector database build completed successfully!")

    except Exception as e:
        logger.error(f"Script execution failed: {str(e)}")
        sys.exit(1)
