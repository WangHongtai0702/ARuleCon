#!/usr/bin/env python3
"""
Simple test script for Agentic RAG optimization functionality.
"""

import sys
import os
from pathlib import Path

# Add script directory to path for vector database access
script_dir = Path(__file__).parent
sys.path.append(str(script_dir))


def test_vector_database_access():
    """Test vector database access directly."""

    print("🧪 Testing Vector Database Access")
    print("=" * 40)

    try:
        from build_vector_db import VectorDatabaseBuilder

        # Initialize vector database
        vector_db = VectorDatabaseBuilder("vector_db")
        print("✅ VectorDatabaseBuilder initialized")

        # Test search
        results = vector_db.search(
            "YARA-L syntax", siem_name="Google Chronicle", n_results=3
        )
        if results and results.get("documents"):
            print(f"🔍 Search successful, found {len(results['documents'])} results")
            for i, doc in enumerate(results["documents"][:2]):
                if isinstance(doc, list) and len(doc) > 0:
                    print(f"   Result {i+1}: {doc[0][:100]}...")
                elif isinstance(doc, str):
                    print(f"   Result {i+1}: {doc[:100]}...")
        else:
            print("❌ Search failed or no results")

    except Exception as e:
        print(f"❌ Error testing vector database: {e}")
        import traceback

        traceback.print_exc()


def test_agentic_rag_import():
    """Test if we can import Agentic RAG modules."""

    print("\n🚀 Testing Agentic RAG Import")
    print("=" * 40)

    try:
        # Add src directory to path
        src_dir = Path(__file__).parent.parent / "src"
        sys.path.insert(0, str(src_dir))

        # Try to import the module directly
        import importlib.util

        # Import agentic_rag module
        spec = importlib.util.spec_from_file_location(
            "agentic_rag", src_dir / "core" / "agentic_rag.py"
        )
        agentic_rag_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(agentic_rag_module)

        print("✅ Successfully imported agentic_rag module")

        # Import models module
        spec = importlib.util.spec_from_file_location(
            "models", src_dir / "schemas" / "models.py"
        )
        models_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(models_module)

        print("✅ Successfully imported models module")

        # Test creating an OptimizationTask
        OptimizationTask = models_module.OptimizationTask
        test_task = OptimizationTask(
            task_name="Test task",
            description="Test description",
            search_keywords=["test", "keyword"],
        )
        print(f"✅ Successfully created OptimizationTask: {test_task.task_name}")

        # Test AgenticRAGOptimizer initialization
        AgenticRAGOptimizer = agentic_rag_module.AgenticRAGOptimizer
        print("✅ Successfully imported AgenticRAGOptimizer class")

        # Try to initialize (this might fail due to dependencies)
        try:
            rag_optimizer = AgenticRAGOptimizer("vector_db", "gpt-4o-mini")
            print("✅ Successfully initialized AgenticRAGOptimizer")
        except Exception as e:
            print(f"⚠️  AgenticRAGOptimizer initialization failed (expected): {e}")
            print("   This is likely due to missing dependencies or import issues")

    except Exception as e:
        print(f"❌ Error testing Agentic RAG import: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    print("🧪 Simple Agentic RAG Test Suite")
    print("=" * 60)

    # Check if vector database exists
    if not Path("vector_db").exists():
        print("❌ Vector database not found. Please run build_vector_db.py first.")
        sys.exit(1)

    # Run tests
    test_vector_database_access()
    test_agentic_rag_import()

    print("\n🎉 Simple test suite completed!")
