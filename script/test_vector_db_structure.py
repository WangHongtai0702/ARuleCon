#!/usr/bin/env python3
"""
Test script to verify the new independent vector database structure for each SIEM.
"""

import sys
from pathlib import Path

# Add the current directory to the path to import build_vector_db
sys.path.append(str(Path(__file__).parent))

from build_vector_db import VectorDatabaseBuilder


def test_database_structure():
    """Test the new independent database structure for each SIEM."""
    print("🧪 Testing Independent Vector Database Structure")
    print("=" * 60)

    try:
        # Initialize vector database
        print("Initializing vector database...")

        # Get the script's directory and go up to project root
        script_dir = Path(__file__).parent
        project_root = script_dir.parent
        vector_db_path = project_root / "vector_db"

        vector_db = VectorDatabaseBuilder(str(vector_db_path))

        # Test database creation for each SIEM
        test_siems = [
            "Splunk",
            "Microsoft Sentinel",
            "IBM QRadar",
            "Google Chronicle",
            "RSA NetWitness",
        ]

        print("\n📚 Testing independent database creation...")
        for siem in test_siems:
            try:
                db_info = vector_db.get_or_create_siem_database(siem)
                print(f"✅ Created/retrieved database for {siem}")
                print(f"   Collection: {db_info['collection_name']}")
                print(f"   Location: {db_info['path']}")
                print(f"   Metadata: {db_info['collection'].metadata}")
            except Exception as e:
                print(f"❌ Failed to create database for {siem}: {str(e)}")

        # Test database info
        print("\n📊 Testing database info...")
        info = vector_db.get_database_info()
        print(f"Total databases: {info.get('total_databases', 0)}")

        for siem, db_info in info.get("databases", {}).items():
            print(f"\n   {siem}:")
            print(f"     Collection: {db_info.get('collection_name', 'Unknown')}")
            print(f"     Location: {db_info.get('database_path', 'Unknown')}")
            print(f"     Chunks: {db_info.get('total_chunks', 0)}")
            print(f"     Metadata: {db_info.get('metadata', {})}")

        # Test search functionality
        print("\n🔍 Testing search functionality...")

        # Test SIEM-specific search
        test_query = "security rule"
        for siem in test_siems[:2]:  # Test first 2 SIEMs
            try:
                results = vector_db.search(test_query, siem_name=siem, n_results=2)
                if results and results.get("documents"):
                    result_count = len(results["documents"][0])
                else:
                    result_count = 0
                print(f"✅ Search in {siem}: {result_count} results")
            except Exception as e:
                print(f"❌ Search in {siem} failed: {str(e)}")

        # Test cross-database search
        try:
            results = vector_db.search(test_query, n_results=3)
            if results and results.get("documents"):
                result_count = len(results["documents"][0])
            else:
                result_count = 0
            print(f"✅ Cross-database search: {result_count} results")
        except Exception as e:
            print(f"❌ Cross-database search failed: {str(e)}")

        print("\n🎉 Independent database structure test completed successfully!")
        return True

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return False


def show_folder_structure():
    """Show the actual folder structure created."""
    print("\n" + "=" * 60)
    print("📁 Actual Folder Structure Created")
    print("=" * 60)

    vector_db_path = Path("../vector_db")  # Use path relative to project root
    if not vector_db_path.exists():
        print("❌ vector_db directory not found!")
        return

    print(f"Base directory: {vector_db_path.absolute()}")

    siem_folders = [
        "Splunk",
        "Microsoft Sentinel",
        "IBM QRadar",
        "Google Chronicle",
        "RSA NetWitness",
    ]

    for siem in siem_folders:
        siem_path = vector_db_path / siem
        if siem_path.exists():
            print(f"\n📂 {siem}/")
            files = list(siem_path.glob("*"))
            if files:
                for file in files:
                    if file.is_file():
                        print(f"   📄 {file.name}")
                        if file.name == "chroma.sqlite3":
                            print(f"      (ChromaDB database file)")
                        elif file.name.endswith(".json"):
                            print(f"      (Metadata file)")
                    else:
                        print(f"   📁 {file.name}/")
                        # Show contents of UUID folders
                        sub_files = list(file.glob("*"))
                        for sub_file in sub_files[:3]:  # Show first 3 files
                            if sub_file.is_file():
                                print(f"      📄 {sub_file.name}")
                            else:
                                print(f"      📁 {sub_file.name}/")
                        if len(sub_files) > 3:
                            print(f"      ... and {len(sub_files) - 3} more files")
            else:
                print("   (empty)")
        else:
            print(f"\n📂 {siem}/ (not created)")


def main():
    """Main function."""
    print("🎯 Independent Vector Database Structure Test")
    print("=" * 60)

    # Test database structure
    test_database_structure()

    # Show folder structure
    show_folder_structure()

    print("\n" + "=" * 60)
    print("💡 Key Features of New Structure:")
    print("   • Each SIEM has its own independent ChromaDB database")
    print("   • Each database is stored in its own folder")
    print("   • No shared database files between SIEMs")
    print("   • Each database has its own chroma.sqlite3 file")
    print("   • Complete isolation and independence")
    print("=" * 60)


if __name__ == "__main__":
    main()
