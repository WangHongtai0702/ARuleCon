#!/usr/bin/env python3
"""
Interactive Vector Database Query Tool for SIEM Documentation

This script provides an interactive interface to query the vector database
built from SIEM documentation PDFs.
"""

import sys
import os
from pathlib import Path

# Add the parent directory to the path to import build_vector_db
sys.path.append(str(Path(__file__).parent))

from build_vector_db import VectorDatabaseBuilder


def main():
    """Main function to demonstrate vector database queries."""

    print("🔍 SIEM Documentation Vector Database Query Tool")
    print("=" * 50)

    try:
        # Initialize vector database
        print("Initializing vector database...")

        # Get the script's directory and go up to project root
        script_dir = Path(__file__).parent
        project_root = script_dir.parent
        vector_db_path = project_root / "vector_db"

        vector_db = VectorDatabaseBuilder(str(vector_db_path))

        # Get database info
        info = vector_db.get_database_info()
        print(f"\n📊 Database Information:")
        print(f"   Total Databases: {info.get('total_databases', 0)}")
        print(f"   Base Path: {info.get('base_path', 'Unknown')}")

        if info.get("databases"):
            print(f"\n📚 Available SIEM Databases:")
            for siem, db_info in info["databases"].items():
                chunks = db_info.get("total_chunks", 0)
                collection_name = db_info.get("collection_name", "Unknown")
                db_path = db_info.get("database_path", "Unknown")
                print(f"   • {siem}: {collection_name} ({chunks} chunks)")
                print(f"     Location: {db_path}")
        else:
            print("   No databases found. Please run build_vector_db.py first.")
            return False

        print()

        # Interactive query loop
        while True:
            print("\n" + "=" * 50)
            print("Query Options:")
            print("1. Search specific SIEM")
            print("2. Search across all SIEMs")
            print("3. Show database details")
            print("4. Quit")

            choice = input("\nEnter your choice (1-4): ").strip()

            if choice == "4":
                break
            elif choice == "1":
                # Search specific SIEM
                print("\nAvailable SIEMs:")
                for i, siem in enumerate(info.get("databases", {}).keys(), 1):
                    print(f"   {i}. {siem}")

                try:
                    siem_choice = int(input("\nSelect SIEM (enter number): ").strip())
                    siem_list = list(info.get("databases", {}).keys())
                    if 1 <= siem_choice <= len(siem_list):
                        selected_siem = siem_list[siem_choice - 1]
                        query = input(f"\nEnter query for {selected_siem}: ").strip()

                        if query:
                            print(f"\n🔍 Searching {selected_siem} for: '{query}'")
                            print("-" * 40)

                            results = vector_db.search(
                                query, siem_name=selected_siem, n_results=3
                            )
                            display_results(results, selected_siem)
                    else:
                        print("❌ Invalid selection")
                except ValueError:
                    print("❌ Please enter a valid number")

            elif choice == "2":
                # Search across all SIEMs
                query = input("\nEnter query to search across all SIEMs: ").strip()

                if query:
                    print(f"\n🔍 Searching all SIEMs for: '{query}'")
                    print("-" * 40)

                    results = vector_db.search(query, n_results=5)
                    display_results(results, "All SIEMs")

            elif choice == "3":
                # Show database details
                print("\n📊 Database Details:")
                for siem, db_info in info.get("databases", {}).items():
                    print(f"\n   {siem}:")
                    print(
                        f"     Collection: {db_info.get('collection_name', 'Unknown')}"
                    )
                    print(f"     Location: {db_info.get('database_path', 'Unknown')}")
                    print(f"     Total Chunks: {db_info.get('total_chunks', 0)}")
                    if db_info.get("metadata"):
                        print(
                            f"     Description: {db_info['metadata'].get('description', 'N/A')}"
                        )
                        print(
                            f"     Created: {db_info['metadata'].get('created_at', 'N/A')}"
                        )
            else:
                print("❌ Invalid choice. Please enter 1-4.")

        print("\n👋 Goodbye!")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

    return True


def display_results(results, source):
    """Display search results in a formatted way."""
    if results and results.get("documents"):
        print(f"\n📄 Results from {source}:")
        for i, doc in enumerate(results["documents"][0]):
            metadata = results["metadatas"][0][i] if results.get("metadatas") else {}

            print(f"\n   Result {i+1}:")
            print(f"      Source: {metadata.get('siem', 'Unknown')}")
            print(f"      File: {metadata.get('filename', 'Unknown')}")
            print(f"      Section: {metadata.get('section_header', 'Unknown')}")
            print(f"      Content: {doc[:200]}...")

            if len(doc) > 200:
                print(f"      [Content truncated. Full length: {len(doc)} characters]")
    else:
        print("❌ No results found")


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
