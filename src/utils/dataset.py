"""
SIEM Rule Dataset Iterator
Provides iterators for different SIEM rule data sources.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Iterator, Dict, Any, Optional, List, Union
from dataclasses import dataclass

# Import settings for path configuration
import sys

sys.path.append(str(Path(__file__).parent.parent.parent))
from settings import (
    get_rule_path,
    get_doc_path,
    get_file_extensions,
    SUPPORTED_SIEM_TYPES,
    SIEM_FILE_EXTENSIONS,
)


@dataclass
class RuleData:
    """Container for rule data with metadata."""

    siem_type: str
    rule_name: str
    rule_content: str
    file_path: Path
    file_type: str
    # Extracted rule components
    search_query: str = ""
    description: str = ""
    author: str = ""
    status: str = ""
    severity: str = ""
    tags: List[str] = None
    data_sources: List[str] = None
    mitre_attack_ids: List[str] = None
    # Raw parsed data
    parsed_data: Dict[str, Any] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.data_sources is None:
            self.data_sources = []
        if self.mitre_attack_ids is None:
            self.mitre_attack_ids = []
        if self.parsed_data is None:
            self.parsed_data = {}
        if self.metadata is None:
            self.metadata = {}


class SIEMRuleDataset:
    """Main dataset class for iterating over SIEM rules."""

    def __init__(self, siem_type: str, rule_type: str = None):
        """
        Initialize dataset for a specific SIEM type.

        Args:
            siem_type: Type of SIEM (e.g., 'Splunk', 'Microsoft Sentinel')
            rule_type: Specific rule type (e.g., 'detections', 'macros')
        """
        if siem_type not in SUPPORTED_SIEM_TYPES:
            raise ValueError(f"Unsupported SIEM type: {siem_type}")

        self.siem_type = siem_type
        self.rule_type = rule_type
        self.rule_path = get_rule_path(siem_type, rule_type)
        self.file_extensions = get_file_extensions(siem_type)

        # Validate path exists
        if not self.rule_path.exists():
            raise FileNotFoundError(f"Rule path does not exist: {self.rule_path}")

    def __iter__(self) -> Iterator[RuleData]:
        """Iterate over all rule files in the dataset."""
        return self._iterate_rules()

    def _iterate_rules(self) -> Iterator[RuleData]:
        """Internal method to iterate over rule files."""
        for file_path in self._get_rule_files():
            try:
                rule_data = self._load_rule_file(file_path)
                if rule_data:
                    yield rule_data
            except Exception as e:
                print(f"Warning: Failed to load rule file {file_path}: {e}")
                continue

    def _get_rule_files(self) -> List[Path]:
        """Get all rule files matching the SIEM type extensions."""
        rule_files = []

        for ext in self.file_extensions:
            pattern = f"**/*{ext}"
            rule_files.extend(self.rule_path.glob(pattern))

        return sorted(rule_files)

    def _load_rule_file(self, file_path: Path) -> Optional[RuleData]:
        """Load a single rule file and return RuleData object."""
        try:
            # Read file content
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse based on file extension
            parsed_data = self._parse_rule_content(content, file_path.suffix)

            # Extract rule name
            rule_name = self._extract_rule_name(file_path, parsed_data)

            # Extract SIEM-specific rule components
            rule_components = self._extract_rule_components(
                parsed_data, file_path.suffix
            )

            # Create metadata
            metadata = {
                "file_size": file_path.stat().st_size,
                "file_modified": file_path.stat().st_mtime,
                "relative_path": str(file_path.relative_to(self.rule_path)),
            }

            return RuleData(
                siem_type=self.siem_type,
                rule_name=rule_name,
                rule_content=content,
                file_path=file_path,
                file_type=file_path.suffix,
                search_query=rule_components.get("search_query", ""),
                description=rule_components.get("description", ""),
                author=rule_components.get("author", ""),
                status=rule_components.get("status", ""),
                severity=rule_components.get("severity", ""),
                tags=rule_components.get("tags", []),
                data_sources=rule_components.get("data_sources", []),
                mitre_attack_ids=rule_components.get("mitre_attack_ids", []),
                parsed_data=parsed_data,
                metadata=metadata,
            )

        except Exception as e:
            print(f"Error loading rule file {file_path}: {e}")
            return None

    def _parse_rule_content(self, content: str, file_extension: str) -> Dict[str, Any]:
        """Parse rule content based on file extension."""
        if file_extension in [".yml", ".yaml"]:
            try:
                return yaml.safe_load(content) or {}
            except yaml.YAMLError as e:
                print(f"YAML parsing error: {e}")
                return {"raw_content": content}

        elif file_extension == ".yaral":
            # YARA-L files are typically plain text
            return {"raw_content": content}

        elif file_extension == ".txt":
            # Plain text files
            return {"raw_content": content}

        elif file_extension in [".ftl", ".properties", ".xml"]:
            # RSA NetWitness files
            return {"raw_content": content}

        else:
            return {"raw_content": content}

    def _extract_rule_name(self, file_path: Path, parsed_data: Dict[str, Any]) -> str:
        """Extract rule name from file path or parsed data."""
        # Try to get name from parsed data first
        if isinstance(parsed_data, dict):
            # Common field names for rule names
            name_fields = ["name", "title", "id", "displayName", "rule_name"]
            for field in name_fields:
                if field in parsed_data and parsed_data[field]:
                    return str(parsed_data[field])

        # Fallback to filename without extension
        return file_path.stem

    def _extract_rule_components(
        self, parsed_data: Dict[str, Any], file_extension: str
    ) -> Dict[str, Any]:
        """Extract SIEM-specific rule components from parsed data."""
        components = {
            "search_query": "",
            "description": "",
            "author": "",
            "status": "",
            "severity": "",
            "tags": [],
            "data_sources": [],
            "mitre_attack_ids": [],
        }

        if not isinstance(parsed_data, dict):
            return components

        # Extract based on SIEM type
        if self.siem_type == "Splunk":
            components.update(self._extract_splunk_components(parsed_data))
        elif self.siem_type == "Microsoft Sentinel":
            components.update(self._extract_sentinel_components(parsed_data))
        elif self.siem_type == "Google Chronicle":
            components.update(self._extract_chronicle_components(parsed_data))
        elif self.siem_type == "IBM QRadar":
            components.update(self._extract_qradar_components(parsed_data))
        elif self.siem_type == "RSA NetWitness":
            components.update(
                self._extract_netwitness_components(parsed_data, file_extension)
            )

        return components

    def _extract_splunk_components(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract components from Splunk rule data."""
        components = {}

        # Search query (most important for Splunk)
        components["search_query"] = parsed_data.get("search", "")

        # Basic metadata
        components["description"] = parsed_data.get("description", "")
        components["author"] = parsed_data.get("author", "")
        components["status"] = parsed_data.get("status", "")

        # Tags (Splunk uses nested tag structure)
        tags = []
        if "tags" in parsed_data and isinstance(parsed_data["tags"], dict):
            for key, value in parsed_data["tags"].items():
                if isinstance(value, list):
                    tags.extend([f"{key}:{v}" for v in value])
                else:
                    tags.append(f"{key}:{value}")
        components["tags"] = tags

        # Data sources
        data_sources = parsed_data.get("data_source", [])
        if isinstance(data_sources, str):
            data_sources = [data_sources]
        components["data_sources"] = data_sources

        # MITRE ATT&CK IDs
        mitre_ids = []
        if "tags" in parsed_data and isinstance(parsed_data["tags"], dict):
            mitre_attack = parsed_data["tags"].get("mitre_attack_id", [])
            if isinstance(mitre_attack, list):
                mitre_ids.extend(mitre_attack)
            elif isinstance(mitre_attack, str):
                mitre_ids.append(mitre_attack)
        components["mitre_attack_ids"] = mitre_ids

        return components

    def _extract_sentinel_components(
        self, parsed_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract components from Microsoft Sentinel rule data."""
        components = {}

        # Search query (called 'query' in Sentinel)
        components["search_query"] = parsed_data.get("query", "")

        # Basic metadata
        components["description"] = parsed_data.get("description", "")
        components["author"] = parsed_data.get("author", "")
        components["severity"] = parsed_data.get("severity", "")

        # Tags
        tags = []
        if "tags" in parsed_data and isinstance(parsed_data["tags"], list):
            for tag in parsed_data["tags"]:
                if isinstance(tag, dict) and "Id" in tag:
                    tags.append(tag["Id"])
                elif isinstance(tag, str):
                    tags.append(tag)
        components["tags"] = tags

        # Data sources
        data_sources = parsed_data.get("requiredDataConnectors", [])
        components["data_sources"] = data_sources

        # MITRE ATT&CK IDs
        mitre_ids = []
        tactics = parsed_data.get("tactics", [])
        techniques = parsed_data.get("relevantTechniques", [])
        mitre_ids.extend(tactics)
        mitre_ids.extend(techniques)
        components["mitre_attack_ids"] = mitre_ids

        return components

    def _extract_chronicle_components(
        self, parsed_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract components from Google Chronicle rule data."""
        components = {}

        # Chronicle rules are in YARA-L format, extract from raw content
        raw_content = parsed_data.get("raw_content", "")

        # Extract rule body by removing comment header
        rule_body = self._extract_yara_rule_body(raw_content)
        components["search_query"] = rule_body

        # Basic metadata extraction
        components["description"] = "Google Chronicle YARA-L Rule"
        components["author"] = "Google Chronicle"
        components["severity"] = "Medium"
        components["tags"] = ["chronicle", "yaral"]
        components["data_sources"] = ["Chronicle"]

        return components

    def _extract_qradar_components(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract components from IBM QRadar rule data."""
        components = {}

        # QRadar rules are typically in text format
        raw_content = parsed_data.get("raw_content", "")

        # Extract search query (look for search patterns)
        search_query = self._extract_qradar_search(raw_content)
        components["search_query"] = search_query

        # Basic extraction from filename and content
        components["description"] = (
            raw_content[:200] + "..." if len(raw_content) > 200 else raw_content
        )
        components["author"] = "QRadar Community"
        components["status"] = "community"

        return components

    def _extract_netwitness_components(
        self, parsed_data: Dict[str, Any], file_extension: str
    ) -> Dict[str, Any]:
        """Extract components from RSA NetWitness rule data."""
        components = {}

        # NetWitness rules are in various formats
        raw_content = parsed_data.get("raw_content", "")

        # Extract search query from FTL files only
        if file_extension == ".ftl":
            search_query = self._extract_ftl_search(raw_content)
            components["search_query"] = search_query
        else:
            # For non-FTL files, use basic content
            components["search_query"] = (
                raw_content[:200] + "..." if len(raw_content) > 200 else raw_content
            )

        # Basic extraction
        components["description"] = (
            raw_content[:200] + "..." if len(raw_content) > 200 else raw_content
        )
        components["author"] = "RSA NetWitness"
        components["status"] = "community"

        return components

    def _extract_yara_rule_body(self, content: str) -> str:
        """Extract YARA-L rule body by removing comment header."""
        import re

        # Find the start of the actual rule (after comment block)
        # Look for the first occurrence of 'rule ' that's not in a comment
        lines = content.split("\n")
        rule_start_line = -1

        for i, line in enumerate(lines):
            # Skip empty lines and comment lines
            if (
                not line.strip()
                or line.strip().startswith("/*")
                or line.strip().startswith("*")
                or line.strip().startswith("//")
            ):
                continue
            # Look for 'rule ' keyword
            if (
                "rule " in line
                and not line.strip().startswith("/*")
                and not line.strip().startswith("*")
            ):
                rule_start_line = i
                break

        if rule_start_line >= 0:
            # Return everything from the rule start to the end
            rule_body = "\n".join(lines[rule_start_line:])
            return rule_body.strip()

        # Fallback: return the original content if no rule found
        return content.strip()

    def _extract_yara_events(self, content: str) -> str:
        """Extract events section from YARA-L content."""
        import re

        events_match = re.search(
            r"events:\s*\n(.*?)(?=\n\s*\w+:|$)", content, re.DOTALL
        )
        if events_match:
            return events_match.group(1).strip()
        return ""

    def _extract_yara_meta(self, content: str) -> Dict[str, str]:
        """Extract meta section from YARA-L content."""
        import re

        meta_data = {}
        meta_match = re.search(r"meta:\s*\n(.*?)(?=\n\s*\w+:|$)", content, re.DOTALL)
        if meta_match:
            meta_content = meta_match.group(1)
            # Extract key-value pairs
            for line in meta_content.split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip("\"'")
                    meta_data[key] = value
        return meta_data

    def _extract_qradar_search(self, content: str) -> str:
        """Extract QRadar rule body (content before first blank line)."""
        lines = content.split("\n")
        rule_lines = []

        for line in lines:
            # Stop at first blank line
            if not line.strip():
                break
            # Skip empty lines at the beginning
            if line.strip():
                rule_lines.append(line.strip())

        if rule_lines:
            return "\n".join(rule_lines)

        # Fallback: return first 100 characters if no rule found
        return content[:100] + "..." if len(content) > 100 else content

    def _extract_ftl_search(self, content: str) -> str:
        """Extract FTL rule body (content from first SELECT to end)."""
        lines = content.split("\n")
        select_start_line = -1

        # Find the first line containing "SELECT"
        for i, line in enumerate(lines):
            if "SELECT" in line.upper():
                select_start_line = i
                break

        if select_start_line >= 0:
            # Return everything from SELECT line to the end
            rule_body = "\n".join(lines[select_start_line:])
            return rule_body.strip()

        # Fallback: return first 100 characters if no SELECT found
        return content[:100] + "..." if len(content) > 100 else content

    def get_rule_count(self) -> int:
        """Get total number of rule files."""
        return len(self._get_rule_files())

    def get_rules_by_category(self, category: str) -> Iterator[RuleData]:
        """Get rules filtered by category (subdirectory)."""
        category_path = self.rule_path / category
        if not category_path.exists():
            return iter([])

        for file_path in category_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in self.file_extensions:
                try:
                    rule_data = self._load_rule_file(file_path)
                    if rule_data:
                        yield rule_data
                except Exception as e:
                    print(f"Warning: Failed to load rule file {file_path}: {e}")
                    continue

    def search_rules(self, keyword: str) -> Iterator[RuleData]:
        """Search rules by keyword in content or name."""
        keyword_lower = keyword.lower()

        for rule_data in self:
            # Search in rule name
            if keyword_lower in rule_data.rule_name.lower():
                yield rule_data
                continue

            # Search in rule content
            if keyword_lower in rule_data.rule_content.lower():
                yield rule_data
                continue

            # Search in parsed metadata
            if rule_data.metadata and "parsed_data" in rule_data.metadata:
                parsed_data = rule_data.metadata["parsed_data"]
                if isinstance(parsed_data, dict):
                    for value in parsed_data.values():
                        if isinstance(value, str) and keyword_lower in value.lower():
                            yield rule_data
                            break


class MultiSIEMDataset:
    """Dataset class for iterating over multiple SIEM types."""

    def __init__(self, siem_types: List[str] = None):
        """
        Initialize dataset for multiple SIEM types.

        Args:
            siem_types: List of SIEM types to include. If None, includes all supported types.
        """
        self.siem_types = siem_types or SUPPORTED_SIEM_TYPES
        self.datasets = {}

        # Initialize datasets for each SIEM type
        for siem_type in self.siem_types:
            try:
                self.datasets[siem_type] = SIEMRuleDataset(siem_type)
            except Exception as e:
                print(f"Warning: Failed to initialize dataset for {siem_type}: {e}")

    def __iter__(self) -> Iterator[RuleData]:
        """Iterate over all rules from all SIEM types."""
        for siem_type, dataset in self.datasets.items():
            for rule_data in dataset:
                yield rule_data

    def get_siem_dataset(self, siem_type: str) -> Optional[SIEMRuleDataset]:
        """Get dataset for a specific SIEM type."""
        return self.datasets.get(siem_type)

    def get_total_rule_count(self) -> int:
        """Get total number of rules across all SIEM types."""
        return sum(dataset.get_rule_count() for dataset in self.datasets.values())

    def get_rules_by_siem(self, siem_type: str) -> Iterator[RuleData]:
        """Get rules for a specific SIEM type."""
        dataset = self.get_siem_dataset(siem_type)
        if dataset:
            return iter(dataset)
        return iter([])


# Convenience functions
def get_siem_dataset(siem_type: str, rule_type: str = None) -> SIEMRuleDataset:
    """Get dataset for a specific SIEM type."""
    return SIEMRuleDataset(siem_type, rule_type)


def get_multi_siem_dataset(siem_types: List[str] = None) -> MultiSIEMDataset:
    """Get dataset for multiple SIEM types."""
    return MultiSIEMDataset(siem_types)


def list_available_siem_types() -> List[str]:
    """List all available SIEM types."""
    return SUPPORTED_SIEM_TYPES.copy()


# Example usage
if __name__ == "__main__":
    print("=== SIEM Rule Dataset Example ===\n")

    # Example 1: Single SIEM dataset
    print("1. Splunk Rules:")
    try:
        splunk_dataset = get_siem_dataset("Splunk")
        print(f"   Total rules: {splunk_dataset.get_rule_count()}")

        # Show first 3 rules with extracted components
        for i, rule in enumerate(splunk_dataset):
            if i >= 3:
                break
            print(f"   - {rule.rule_name} ({rule.file_type})")
            print(
                f"     Search Query: {rule.search_query[:100]}..."
                if len(rule.search_query) > 100
                else f"     Search Query: {rule.search_query}"
            )
            print(f"     Author: {rule.author}")
            print(f"     Status: {rule.status}")
            print(
                f"     Tags: {', '.join(rule.tags[:3])}"
                if rule.tags
                else "     Tags: None"
            )
            print()
    except Exception as e:
        print(f"   Error: {e}")

    print()

    # Example 2: Multi-SIEM dataset
    print("2. All SIEM Rules:")
    try:
        multi_dataset = get_multi_siem_dataset()
        print(
            f"   Total rules across all SIEMs: {multi_dataset.get_total_rule_count()}"
        )

        # Show count by SIEM type
        for siem_type in multi_dataset.siem_types:
            dataset = multi_dataset.get_siem_dataset(siem_type)
            if dataset:
                print(f"   - {siem_type}: {dataset.get_rule_count()} rules")
    except Exception as e:
        print(f"   Error: {e}")

    print()

    # Example 3: Search functionality
    print("3. Search Example (looking for 'authentication'):")
    try:
        splunk_dataset = get_siem_dataset("Splunk")
        search_results = list(splunk_dataset.search_rules("authentication"))
        print(f"   Found {len(search_results)} rules containing 'authentication'")

        for rule in search_results[:3]:  # Show first 3 results
            print(f"   - {rule.rule_name}")
    except Exception as e:
        print(f"   Error: {e}")
